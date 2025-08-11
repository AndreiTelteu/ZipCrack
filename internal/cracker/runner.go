package cracker

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	PerThread []uint64
	Total     uint64
	Timestamp time.Time
}

type Result struct {
	Found    bool
	Password string
}

type Config struct {
	ZipBytes      []byte
	Alphabet      []rune
	MinLen        int
	MaxLen        int
	Workers       int
	BatchSize     int
	ReportEvery   time.Duration
	FoundCallback func(pw string)
}

// Runner coordinates generation, workers, stats, and result publishing.
type Runner struct {
	cfg      Config
	statsCh  chan Stats
	resultCh chan Result

	onceResult sync.Once
	result     Result

	// per-thread attempt counters
	counters []uint64

	// internal cancel used by runner when found; external ctx can also cancel
	cancel func()
}

func NewRunner(cfg Config) (*Runner, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1024
	}
	if cfg.ReportEvery <= 0 {
		cfg.ReportEvery = 2 * time.Second
	}
	r := &Runner{
		cfg:      cfg,
		statsCh:  make(chan Stats, 8),
		resultCh: make(chan Result, 1),
		counters: make([]uint64, cfg.Workers),
	}
	return r, nil
}

func (r *Runner) StatsCh() <-chan Stats   { return r.statsCh }
func (r *Runner) ResultCh() <-chan Result { return r.resultCh }
func (r *Runner) GetResult() Result       { return r.result }

func (r *Runner) publishResult(res Result) {
	r.onceResult.Do(func() {
		r.result = res
		select {
		case r.resultCh <- res:
		default:
		}
	})
}

func (r *Runner) Start(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel

	// Prepare ZIP checker
	checker, err := NewZipChecker(r.cfg.ZipBytes)
	if err != nil {
		return err
	}

	// Jobs channel carries batches of password candidates
	jobs := make(chan batch, r.cfg.Workers*2)

	var wg sync.WaitGroup
	// Workers
	for i := 0; i < r.cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case b, ok := <-jobs:
					if !ok {
						return
					}
					// Process batch
					for _, pw := range b {
						if ctx.Err() != nil {
							return
						}
						ok := checker.Try(pw)
						atomic.AddUint64(&r.counters[id], 1)
						if ok {
							// Found! publish and cancel
							r.publishResult(Result{Found: true, Password: pw})
							if r.cfg.FoundCallback != nil {
								r.cfg.FoundCallback(pw)
							}
							if r.cancel != nil {
								r.cancel()
							}
							return
						}
					}
				}
			}
		}(i)
	}

	// Generator
	wg.Add(1)
	go func() {
		defer wg.Done()
		seed := time.Now().UnixNano() ^ int64(r.cfg.Workers) ^ int64(len(r.cfg.Alphabet))
		rng := rand.New(rand.NewSource(seed))
		for {
			if ctx.Err() != nil {
				return
			}
			b := generateBatch(r.cfg.Alphabet, r.cfg.MinLen, r.cfg.MaxLen, r.cfg.BatchSize, rng)
			select {
			case jobs <- b:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Stats publisher
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(r.cfg.ReportEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				per := make([]uint64, len(r.counters))
				var total uint64
				for i := range r.counters {
					v := atomic.LoadUint64(&r.counters[i])
					per[i] = v
					total += v
				}
				s := Stats{PerThread: per, Total: total, Timestamp: now}
				select {
				case r.statsCh <- s:
				default:
					// drop if UI is slow; next tick will carry new data
				}
			}
		}
	}()

	// Wait for completion
	go func() {
		wg.Wait()
		close(jobs)
		close(r.statsCh)
		// If no password found, publish final not found
		if !r.result.Found {
			r.publishResult(Result{Found: false})
		}
		close(r.resultCh)
	}()

	return nil
}
