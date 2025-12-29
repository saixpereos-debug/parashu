package adaptive

import (
	"sync"
	"time"
)

// Engine manages the adaptive scanning state
type Engine struct {
	Config     ScanConfig
	currentC   int
	latencyAvg time.Duration
	errorCount int
	mu         sync.Mutex
}

// NewEngine creates a new adaptive engine with a starting config
func NewEngine(cfg ScanConfig) *Engine {
	return &Engine{
		Config:   cfg,
		currentC: cfg.InitialConcurrency,
	}
}

// Concurrency returns the current recommended concurrency
func (e *Engine) Concurrency() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.currentC
}

// Timeout calculates a dynamic timeout based on latency and config
func (e *Engine) Timeout() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Simple adaptive logic: 2x latency or MinTimeout
	timeout := e.latencyAvg * 2
	if timeout < e.Config.MinTimeout {
		timeout = e.Config.MinTimeout
	}
	if timeout > e.Config.MaxTimeout {
		timeout = e.Config.MaxTimeout
	}
	return timeout
}

// RecordResult feeds scan metrics back into the engine
func (e *Engine) RecordResult(latency time.Duration, success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Update average latency (Exponential Moving Average)
	alpha := 0.2
	if e.latencyAvg == 0 {
		e.latencyAvg = latency
	} else {
		e.latencyAvg = time.Duration((alpha * float64(latency)) + ((1 - alpha) * float64(e.latencyAvg)))
	}

	// Adjust concurrency on failures
	if !success {
		e.errorCount++
		if e.errorCount > 5 {
			e.currentC = int(float64(e.currentC) * 0.75) // Reduce by 25%
			if e.currentC < 1 {
				e.currentC = 1
			}
			e.errorCount = 0
		}
	} else {
		// Slowly increase if stable
		if e.errorCount == 0 && e.currentC < e.Config.InitialConcurrency*2 { // Cap at 2x initial
			e.currentC++
		}
	}
}
