package nethealth

type SocketSnapshot struct {
	ConnectionID string
	Description  string
	Inflight     int64
	Failures     int64
	QueuedBytes  int64
	Connected    bool
}

func (s SocketSnapshot) GetConnectionID() string { return s.ConnectionID }
func (s SocketSnapshot) GetDescription() string  { return s.Description }
func (s SocketSnapshot) GetInflight() int64      { return s.Inflight }
func (s SocketSnapshot) GetFailures() int64      { return s.Failures }
func (s SocketSnapshot) GetQueuedBytes() int64   { return s.QueuedBytes }
func (s SocketSnapshot) IsConnected() bool       { return s.Connected }
