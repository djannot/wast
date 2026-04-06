package commands

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// signalContext returns a context that is cancelled when the process receives
// SIGINT or SIGTERM. Callers should defer the returned cancel function to
// release resources when the context is no longer needed.
//
// This mirrors the pattern used by the serve and intercept commands so that
// scan, crawl, recon, and api commands can all respond gracefully to Ctrl+C.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			cancel()
		case <-ctx.Done():
			// Parent cancelled — stop waiting for signals.
		}
		signal.Stop(sigChan)
	}()
	return ctx, cancel
}
