package tls

import (
	"testing"
)

// type fakeAddr struct {
// }

// func (f *fakeAddr) Network() string {
// 	return "tcp"
// }

// func (f *fakeAddr) String() string {
// 	return "localhost"
// }

// type fakeConn struct {
// 	Data []byte
// }

// func (f *fakeConn) Read(b []byte) (n int, err error) {
// 	return -1, nil
// }

// func (f *fakeConn) Write(b []byte) (n int, err error) {
// 	return -1, nil
// }

// func (f *fakeConn) Close() error {
// 	return nil
// }

// func (f *fakeConn) LocalAddr() net.Addr {
// 	return &fakeAddr{}
// }

// func (f *fakeConn) RemoteAddr() net.Addr {
// 	return &fakeAddr{}
// }

// func (f *fakeConn) SetDeadline(t time.Time) error {
// 	return nil
// }

// func (f *fakeConn) SetReadDeadline(t time.Time) error {
// 	return nil
// }

// func (f *fakeConn) SetWriteDeadline(t time.Time) error {
// 	return nil
// }

// func peerWrite(conn net.Conn, data []byte) {
// 	conn.Write(data)
// }

func TestTLS(t *testing.T) {
	// conn := &fakeConn{}
	// tlsConnect := NewTLSConnect(conn)

	// tlsConnect.SendHello(CLIENT_HELLO)

	// bytes, err := tlsConnect.CreateHello(CLIENT_HELLO)
	// peerWrite(tlsConnect.Conn, bytes)

	// b := make([]byte, 1024)
	// _, _, err := tlsConnect.Read(b)
	// require.NoError(t, err)
	// b = make([]byte, 1024)
	// _, _, err = tlsConnect.Read(b)
	// require.NoError(t, err)
	// b = make([]byte, 1024)
	// _, _, err = tlsConnect.Read(b)
	// require.NoError(t, err)

	// tlsConnect.SendKeyExchange()
	// tlsConnect.SendChangeCipherSpec()
}
