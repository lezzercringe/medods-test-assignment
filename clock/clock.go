package clock

import "time"

type Clock interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

var _ Clock = &STDClock{}

type STDClock struct{}

func (c *STDClock) Now() time.Time {
	return time.Now()
}

func (c *STDClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}
