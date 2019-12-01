package magictls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"testing"
	"time"
)

var (
	testP = x509.NewCertPool()
	pk, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca    *x509.Certificate
)

func init() {
	// initialize some basic stuff for testing
	catpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Issuer:                pkix.Name{CommonName: "localhost"},
		Subject:               pkix.Name{CommonName: "localhost"},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
	}

	caBin, err := x509.CreateCertificate(rand.Reader, catpl, catpl, pk.Public(), pk)
	if err != nil {
		panic(err)
	}
	ca, err = x509.ParseCertificate(caBin)
	if err != nil {
		panic(err)
	}

	testP.AddCert(ca)
}

func TestTLS(t *testing.T) {
	rdy := make(chan int)

	go testSrv(rdy)
	port := <-rdy

	log.Printf("running tests on port %d", port)

	c, err := tls.Dial("tcp", fmt.Sprintf("localhost:%d", port), &tls.Config{RootCAs: testP})
	if err != nil {
		t.Errorf("failed test: %s", err)
		return
	}

	buf, err := ioutil.ReadAll(c)
	c.Close()
	if err != nil {
		t.Errorf("failed read: %s", err)
		return
	}

	if string(buf) != "hello world" {
		t.Errorf("invalid response: %s", buf)
		return
	}

	// test with "A"
	c, err = tls.Dial("tcp", fmt.Sprintf("localhost:%d", port), &tls.Config{RootCAs: testP, NextProtos: []string{"a"}})
	if err != nil {
		t.Errorf("failed test: %s", err)
		return
	}

	buf, err = ioutil.ReadAll(c)
	c.Close()
	if err != nil {
		t.Errorf("failed read: %s", err)
		return
	}

	if string(buf) != "hello from A" {
		t.Errorf("invalid response: %s", buf)
		return
	}

	// test with "B" and proxy protocol
	ctcp, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Errorf("failed connect: %s", err)
		return
	}

	// send proxy line
	fmt.Fprintf(ctcp, "PROXY TCP4 10.0.0.1 10.0.0.2 123 456\r\n")

	// initialize tls
	c = tls.Client(ctcp, &tls.Config{RootCAs: testP, ServerName: "localhost", NextProtos: []string{"b"}})

	buf, err = ioutil.ReadAll(c)
	c.Close()
	if err != nil {
		t.Errorf("failed read: %s", err)
		return
	}

	if string(buf) != "IP = 10.0.0.1:123" {
		t.Errorf("invalid response: %s", buf)
		return
	}
}

func testSrv(rdy chan int) {
	cfg := &tls.Config{
		RootCAs: testP,
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{ca.Raw},
				PrivateKey:  pk,
				Leaf:        ca,
			},
		},
		NextProtos: []string{"a", "b", "c", "d", "e", "f"},
	}

	l, err := Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		// shouldn't happen
		panic(err)
	}

	// return port
	rdy <- l.Addr().(*net.TCPAddr).Port

	if sub, err := l.ProtoListener("a"); err == nil {
		go handleA(sub)
	}
	if sub, err := l.ProtoListener("b"); err == nil {
		go handleB(sub)
	}

	// read loop (default handler)
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %s", err)
			return
		}

		c.Write([]byte("hello world"))
		c.Close()
	}
}

func handleA(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %s", err)
			return
		}

		fmt.Fprintf(c, "hello from A")
		c.Close()
	}
}

func handleB(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %s", err)
			return
		}

		fmt.Fprintf(c, "IP = %s", c.RemoteAddr())
		c.Close()
	}
}
