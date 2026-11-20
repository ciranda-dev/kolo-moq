package kolomoq

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// testTransport allows enough streams for the tests' subscriptions.
var testTransport = &kolotransport.Config{MaxIncomingStreams: 1000}

// checkLeaks fails the test if goroutines started during it outlive it.
func checkLeaks(t *testing.T) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			n := runtime.NumGoroutine()
			if n <= before {
				return
			}
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				buf = buf[:runtime.Stack(buf, true)]
				t.Errorf("goroutines: %d before, %d after\n%s", before, n, filterStacks(string(buf)))
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

func filterStacks(all string) string {
	var out []string
	for _, g := range strings.Split(all, "\n\n") {
		if strings.Contains(g, "kolo-moq") && !strings.Contains(g, "testing.tRunner") {
			out = append(out, g)
		}
	}
	return strings.Join(out, "\n\n")
}

type pair struct {
	client, server *Session
	listener       *kolosecure.Listener
	clientConn     *kolosecure.Conn
	serverConn     *kolosecure.Conn
}

// connect returns the two kolo-secure ends of a loopback connection.
func connect(t *testing.T) (client, server *kolosecure.Conn, l *kolosecure.Listener) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srvID, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	l, err = kolosecure.Listen(ctx, "127.0.0.1:0", srvID, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	type accepted struct {
		conn *kolosecure.Conn
		err  error
	}
	acc := make(chan accepted, 1)
	go func() {
		c, err := l.Accept(ctx)
		acc <- accepted{c, err}
	}()
	client, err = kolosecure.Dial(ctx, l.Addr().String(), cliID, srvID.PublicKey(), &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	a := <-acc
	if a.err != nil {
		t.Fatal(a.err)
	}
	return client, a.conn, l
}

// newPair starts a client and a server session on a loopback kolo-secure
// connection; both close at the end of the test.
func newPair(t *testing.T, clientCfg, serverCfg *Config) *pair {
	t.Helper()
	cc, sc, l := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	type res struct {
		s   *Session
		err error
	}
	srv := make(chan res, 1)
	go func() {
		s, err := NewServer(ctx, sc, serverCfg)
		srv <- res{s, err}
	}()
	client, err := NewClient(ctx, cc, clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	r := <-srv
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() {
		client.Close()
		r.s.Close()
	})
	return &pair{client: client, server: r.s, listener: l, clientConn: cc, serverConn: sc}
}

func newOrigin(t *testing.T) *Origin {
	t.Helper()
	o, err := NewOrigin(nil)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// readN reads n objects from sub.
func readN(t *testing.T, ctx context.Context, sub *Subscription, n int) []Object {
	t.Helper()
	var out []Object
	for len(out) < n {
		o, err := sub.ReadObject(ctx)
		if err != nil {
			t.Fatalf("after %d objects: %v", len(out), err)
		}
		out = append(out, o)
	}
	return out
}

// eventually polls cond until it holds or 10s pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func requestCode(err error) RequestCode {
	var re *RequestError
	if errors.As(err, &re) {
		return re.Code
	}
	return 0xffff
}
