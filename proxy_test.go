package magictls

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"testing"
)

const testStr = "This is a test string. It could really be anything as long as it's unique and longer than 128 bytes. The proxy protocol detector expects at least 128 bytes of input data from the remote peer in order to know we have a proxy thing, but we can add a timeout to that eventually..."

func send(w io.Writer, data ...string) error {
	for _, s := range data {
		b := []byte(s)
		l := len(b)
		binary.Write(w, binary.BigEndian, int32(l))
		w.Write(b)
	}
	return nil
}

func readOne(r io.Reader) string {
	var l int32
	err := binary.Read(r, binary.BigEndian, &l)
	if err != nil {
		return ""
	}
	b := make([]byte, l)
	io.ReadFull(r, b)
	return string(b)
}

type proxyV1test struct {
	proxy  string
	expect string
}

func TestProxy(t *testing.T) {
	rdy := make(chan int)
	go testProxySrv(rdy)
	port := <-rdy

	t.Logf("running tests on port %d", port)

	tests := []proxyV1test{
		proxyV1test{"", ""},
		proxyV1test{"PROXY UNKNOWN\n", ""},
		proxyV1test{"PROXY UNKNOWN\r\n", ""},
		proxyV1test{"PROXY TCP4 1.1.1.1 2.2.2.2 123 456\n", "1.1.1.1:123"},
	}

	for _, test := range tests {
		c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
		if err != nil {
			t.Errorf("failed test %+v: %s", test, err)
			continue
		}

		if test.proxy != "" {
			c.Write([]byte(test.proxy))
		}

		send(c, testStr)

		l1 := readOne(c)
		l2 := readOne(c)
		c.Close()

		if test.expect != "" && l1 != test.expect {
			t.Errorf("expected %s but got %s", test.expect, l1)
		}

		if l2 != testStr {
			t.Errorf("failed, expected string but got %s / %s", l1, l2)
		}
	}
}

func testProxySrv(rdy chan int) {
	l, err := Listen("tcp", "127.0.0.1:0", nil)
	if err != nil {
		// shouldn't happen
		panic(err)
	}

	// return port
	rdy <- l.Addr().(*net.TCPAddr).Port

	// read loop (default handler)
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %s", err)
			return
		}

		data := readOne(c)
		send(c, c.RemoteAddr().String(), data)
		c.Close()
	}
}
