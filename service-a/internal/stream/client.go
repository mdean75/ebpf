package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/balancer"
	"github.com/mdean75/ebpf-grpc-experiment/service-a/internal/metrics"
	pb "github.com/mdean75/ebpf-grpc-experiment/proto/stream"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	heartbeatPrefix   = "hb-"
	lossCheckInterval = 200 * time.Millisecond
	lossDeadline      = 3 * time.Second
	sendQueueDepth    = 256
)

// inFlight tracks a sent message awaiting a response.
type inFlight struct {
	sentAt      time.Time
	isHeartbeat bool
}

// Client manages one persistent bidi gRPC stream to a single VM address.
// The message generator calls Send() to enqueue messages; the client
// handles dialing, reconnection, heartbeats, and loss accounting internally.
type Client struct {
	address string
	bal     *balancer.Balancer
	caCert  string

	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration

	sendCh   chan *pb.Message
	inFlight sync.Map // map[string]*inFlight
	seq      atomic.Uint64

	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewClient(addr string, bal *balancer.Balancer, hbInterval, hbTimeout time.Duration, caCert string) *Client {
	return &Client{
		address:           addr,
		bal:               bal,
		caCert:            caCert,
		heartbeatInterval: hbInterval,
		heartbeatTimeout:  hbTimeout,
		sendCh:            make(chan *pb.Message, sendQueueDepth),
		stopCh:            make(chan struct{}),
	}
}

// Send enqueues a message for transmission on this stream. Non-blocking;
// drops the message and increments MessagesLost if the queue is full
// (indicates the stream is saturated or dead).
func (c *Client) Send(msg *pb.Message) {
	select {
	case c.sendCh <- msg:
		metrics.MessagesSent.WithLabelValues(c.address).Inc()
	default:
		metrics.MessagesLost.WithLabelValues(c.address).Inc()
		log.Printf("stream %s: send queue full, dropping msg id=%s", c.address, msg.Id)
	}
}

// Address returns the VM address this client connects to.
func (c *Client) Address() string {
	return c.address
}

// NextID returns a unique message ID scoped to this client.
func (c *Client) NextID() string {
	return fmt.Sprintf("%s-%d", c.address, c.seq.Add(1))
}

// Start dials the server and runs the stream loop, reconnecting on failure.
// Should be called in a goroutine. Blocks until Stop is called.
func (c *Client) Start() {
	c.wg.Add(1)
	defer c.wg.Done()

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}
		if err := c.runStream(); err != nil {
			log.Printf("stream %s: %v — reconnecting in 1s", c.address, err)
			c.bal.SetHealth(c.address, balancer.Dead, "stream_error")
			metrics.StreamHealth.WithLabelValues(c.address).Set(2)
		}
		select {
		case <-c.stopCh:
			return
		case <-time.After(time.Second):
		}
	}
}

func (c *Client) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *Client) runStream() error {
	conn, err := c.dial()
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		select {
		case <-c.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	grpcClient := pb.NewStreamServiceClient(conn)
	stream, err := grpcClient.BiDiStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	c.bal.SetHealth(c.address, balancer.Healthy, "reconnected")
	metrics.StreamHealth.WithLabelValues(c.address).Set(0)
	log.Printf("stream %s: connected", c.address)

	// Clear stale in-flight entries from the previous stream
	c.inFlight.Range(func(k, _ any) bool {
		c.inFlight.Delete(k)
		return true
	})

	errCh := make(chan error, 2)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- c.sendLoop(stream)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- c.recvLoop(stream)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.heartbeatLoop(stream, ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.lossCheckLoop(ctx)
	}()

	var streamErr error
	select {
	case streamErr = <-errCh:
	case <-c.stopCh:
	}

	cancel()
	wg.Wait()
	return streamErr
}

func (c *Client) sendLoop(stream pb.StreamService_BiDiStreamClient) error {
	for {
		select {
		case <-c.stopCh:
			return nil
		case msg, ok := <-c.sendCh:
			if !ok {
				return nil
			}
			c.inFlight.Store(msg.Id, &inFlight{sentAt: time.Now()})
			if err := stream.Send(msg); err != nil {
				c.bal.SetHealth(c.address, balancer.Dead, "send_error")
				metrics.StreamHealth.WithLabelValues(c.address).Set(2)
				return err
			}
		}
	}
}

func (c *Client) recvLoop(stream pb.StreamService_BiDiStreamClient) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return fmt.Errorf("server closed stream")
		}
		if err != nil {
			return err
		}
		if v, ok := c.inFlight.LoadAndDelete(msg.Id); ok {
			inf := v.(*inFlight)
			metrics.ResponseLatency.WithLabelValues(c.address).Observe(time.Since(inf.sentAt).Seconds())
		}
	}
}

func (c *Client) heartbeatLoop(stream pb.StreamService_BiDiStreamClient, ctx context.Context) {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hbID := fmt.Sprintf("%s%d", heartbeatPrefix, c.seq.Add(1))
			sentAt := time.Now()
			c.inFlight.Store(hbID, &inFlight{sentAt: sentAt, isHeartbeat: true})

			if err := stream.Send(&pb.Message{
				Id:        hbID,
				Timestamp: sentAt.UnixNano(),
			}); err != nil {
				c.inFlight.Delete(hbID)
				return
			}

			// Watch for heartbeat timeout without blocking the ticker
			timeout := c.heartbeatTimeout
			capturedID := hbID
			go func() {
				timer := time.NewTimer(timeout)
				defer timer.Stop()
				select {
				case <-timer.C:
					if _, pending := c.inFlight.LoadAndDelete(capturedID); pending {
						log.Printf("stream %s: heartbeat timeout (id=%s)", c.address, capturedID)
						c.bal.SetHealth(c.address, balancer.Dead, "heartbeat_timeout")
						metrics.StreamHealth.WithLabelValues(c.address).Set(2)
					}
				case <-ctx.Done():
				}
			}()
		}
	}
}

func (c *Client) lossCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(lossCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			c.inFlight.Range(func(k, v any) bool {
				inf := v.(*inFlight)
				if !inf.isHeartbeat && now.Sub(inf.sentAt) > lossDeadline {
					metrics.MessagesLost.WithLabelValues(c.address).Inc()
					c.inFlight.Delete(k)
				}
				return true
			})
		}
	}
}

func (c *Client) dial() (*grpc.ClientConn, error) {
	// No CA cert → plain gRPC without TLS (used for Docker testing where
	// service-a connects directly to service-b with no nginx TLS proxy).
	if c.caCert == "" {
		//nolint:staticcheck
		return grpc.Dial(c.address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	pool := x509.NewCertPool()
	pem, err := os.ReadFile(c.caCert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("parse CA cert failed")
	}
	tlsCfg := &tls.Config{RootCAs: pool}
	//nolint:staticcheck
	return grpc.Dial(c.address, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
}
