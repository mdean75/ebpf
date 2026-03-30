package nethealth

import "fmt"

type SocketFlow struct {
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

func (f SocketFlow) GetLocalIP() string  { return f.LocalIP }
func (f SocketFlow) GetLocalPort() int   { return f.LocalPort }
func (f SocketFlow) GetRemoteIP() string { return f.RemoteIP }
func (f SocketFlow) GetRemotePort() int  { return f.RemotePort }
func (f SocketFlow) ToFlowKey() string {
	return fmt.Sprintf("%s:%d->%s:%d", f.LocalIP, f.LocalPort, f.RemoteIP, f.RemotePort)
}
func (f SocketFlow) AsDisplay() string {
	return fmt.Sprintf("%s:%d -> %s:%d", f.LocalIP, f.LocalPort, f.RemoteIP, f.RemotePort)
}
func (f SocketFlow) Reversed() SocketFlow {
	return SocketFlow{LocalIP: f.RemoteIP, LocalPort: f.RemotePort, RemoteIP: f.LocalIP, RemotePort: f.LocalPort}
}
