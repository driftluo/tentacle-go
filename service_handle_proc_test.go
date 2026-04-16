package tentacle

import (
	"testing"
	"time"
)

func TestServiceHandleProcStopsOnStopSignal(t *testing.T) {
	stop := make(chan struct{})
	proc := serviceHandleProc{
		recv: make(chan any),
		stop: stop,
	}

	done := make(chan struct{})
	go func() {
		proc.run()
		close(done)
	}()

	close(stop)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected service handle proc to stop on stop signal")
	}
}
