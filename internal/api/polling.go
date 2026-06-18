package api

import (
	"context"
	"fmt"
	"time"
)

// Poller polls the PatchFlow API for job status.
type Poller struct {
	Client      APIClient
	Interval    time.Duration
	MaxAttempts int
}

// Poll calls GetStatus in a loop until the job is completed, failed, or max attempts are reached.
// It returns immediately on terminal statuses ("completed", "failed").
// It respects context cancellation.
func (p *Poller) Poll(ctx context.Context, id string) (*StatusResponse, error) {
	interval := p.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	maxAttempts := p.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 60
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, err := p.Client.GetStatus(ctx, id)
		if err != nil {
			return nil, err
		}

		if resp.Status == "completed" || resp.Status == "failed" {
			return resp, nil
		}

		if attempt == maxAttempts {
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}

	return nil, fmt.Errorf("max polling attempts (%d) reached for job %s", maxAttempts, id)
}
