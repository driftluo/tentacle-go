package tentacle

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/driftluo/tentacle-go/secio"
	ma "github.com/multiformats/go-multiaddr"
)

func TestExtractPeerID(t *testing.T) {
	pid := secio.RandomPeerID()

	ip1 := fmt.Sprintf("/ip4/127.0.0.1/tcp/1337/p2p/%s", pid.Bese58String())
	ip2 := fmt.Sprintf("/p2p/%s", pid.Bese58String())

	addr1, _ := ma.NewMultiaddr(ip1)
	pid1, _ := ExtractPeerID(addr1)

	addr2, _ := ma.NewMultiaddr(ip2)
	pid2, _ := ExtractPeerID(addr2)

	if pid.Bese58String() != pid1.Bese58String() {
		t.Fatal("ip1 fail")
	}

	if pid.Bese58String() != pid2.Bese58String() {
		t.Fatal("ip2 fail")
	}
}

func TestDeleteSlice(t *testing.T) {
	m1, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1332/")
	m3, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/133/")
	m4, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1337/")
	m5, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/135/")
	m6, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1347/")
	m7, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1317/")
	m8, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1237/")
	m9, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/137/")

	a := []ma.Multiaddr{
		m1, m2, m3, m4, m5, m1, m6, m7, m8, m9, m1,
	}

	b := deleteSlice(a, m1)

	for _, v := range b {
		if slices.Equal(v, m1) {
			t.Fatal("not delete")
		}
	}
}

func TestContainsMultiaddr(t *testing.T) {
	m1, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1332/")
	m3, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/133/")

	a := []ma.Multiaddr{m1, m2}

	if !containsMultiaddr(a, m1) {
		t.Fatal("expected containsMultiaddr to find existing address")
	}
	if containsMultiaddr(a, m3) {
		t.Fatal("expected containsMultiaddr to reject missing address")
	}
}

func TestSendOrDropResultRunsCleanupWhenStopped(t *testing.T) {
	ch := make(chan string, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	cleaned := make(chan string, 1)
	close(stop)

	go func() {
		sendOrDropResult(ch, stop, "late", func(v string) {
			cleaned <- v
		})
		close(done)
	}()

	select {
	case got := <-cleaned:
		if got != "late" {
			t.Fatalf("expected cleanup value late, got %q", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for dropped result cleanup")
	}

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("sendOrDropResult blocked after cleanup")
	}

	select {
	case got := <-ch:
		t.Fatalf("expected dropped value to stay out of channel, got %q", got)
	default:
	}
}

func TestSendOrDropResultSendsValue(t *testing.T) {
	ch := make(chan string, 1)
	stop := make(chan struct{})
	done := make(chan struct{})
	cleaned := make(chan struct{}, 1)

	go func() {
		sendOrDropResult(ch, stop, "ok", func(string) {
			cleaned <- struct{}{}
		})
		close(done)
	}()

	select {
	case got := <-ch:
		if got != "ok" {
			t.Fatalf("expected ok, got %q", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for delivered result")
	}

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("sendOrDropResult blocked after send")
	}

	select {
	case <-cleaned:
		t.Fatal("unexpected cleanup for delivered result")
	default:
	}
}

func TestSupport(t *testing.T) {
	m1, _ := ma.NewMultiaddr("/ip4/127.0.0.1/tcp/1336/")
	m2, _ := ma.NewMultiaddr("/ip4/127.0.0.1/udp/1336/")
	m3, _ := ma.NewMultiaddr("/dns/www.baidu.com/tcp/1336/")
	m4, _ := ma.NewMultiaddr("/dns/www.baidu.com/tcp/1336/ws")

	if !isSupport(m1) {
		t.Fatal("m1 fail")
	}
	if isSupport(m2) {
		t.Fatal("m2 fail")
	}
	if !isSupport(m3) {
		t.Fatal("m3 fail")
	}
	if !isSupport(m4) {
		t.Fatal("m3 fail")
	}
}
