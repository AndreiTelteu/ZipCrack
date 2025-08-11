package tui

import (
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"zipcrack/internal/cracker"

	tea "github.com/charmbracelet/bubbletea"
)

type Config struct {
	Workers     int
	SampleEvery time.Duration
	StatsCh     <-chan cracker.Stats
	ResultCh    <-chan cracker.Result
	Stop        func()

	// Optional for progress/ETA
	AlphabetLen int
	MinLen      int
	MaxLen      int
}

type statsMsg cracker.Stats
type statsClosedMsg struct{}
type resultMsg cracker.Result
type resultClosedMsg struct{}

func listenStats(ch <-chan cracker.Stats) tea.Cmd {
	return func() tea.Msg {
		s, ok := <-ch
		if !ok {
			return statsClosedMsg{}
		}
		return statsMsg(s)
	}
}

func listenResult(ch <-chan cracker.Result) tea.Cmd {
	return func() tea.Msg {
		r, ok := <-ch
		if !ok {
			return resultClosedMsg{}
		}
		return resultMsg(r)
	}
}

type model struct {
	cfg Config

	perSec     []float64
	lastCounts []uint64
	lastTime   time.Time
	total      uint64

	found    bool
	password string

	statsOpen  bool
	resultOpen bool

	start    time.Time
	idxWidth int // width for thread index padding, e.g., T01, T02...

	// Progress/ETA
	totalComb *big.Int // sum_{k=min..max} (alphabetLen^k)
}

func NewModel(cfg Config) model {
	// Determine digits needed for thread index padding (e.g., 2 digits for up to 99 workers).
	w := 1
	n := cfg.Workers
	for n >= 10 {
		w++
		n /= 10
	}

	m := model{
		cfg:        cfg,
		perSec:     make([]float64, cfg.Workers),
		lastCounts: make([]uint64, cfg.Workers),
		statsOpen:  true,
		resultOpen: true,
		start:      time.Now(),
		idxWidth:   w,
	}

	// Precompute total combinations if parameters are provided
	if cfg.AlphabetLen > 0 && cfg.MaxLen > 0 {
		m.totalComb = computeTotalCombinations(cfg.AlphabetLen, cfg.MinLen, cfg.MaxLen)
	}

	return m
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		listenStats(m.cfg.StatsCh),
		listenResult(m.cfg.ResultCh),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.cfg.Stop != nil {
				m.cfg.Stop()
			}
			return m, tea.Quit
		}
	case statsMsg:
		now := msg.Timestamp
		if m.lastTime.IsZero() {
			m.lastTime = now
			// Initialize snapshot
			copy(m.lastCounts, msg.PerThread)
			m.total = msg.Total
			return m, listenStats(m.cfg.StatsCh)
		}
		dt := now.Sub(m.lastTime).Seconds()
		if dt <= 0 {
			dt = m.cfg.SampleEvery.Seconds()
			if dt <= 0 {
				dt = 2
			}
		}
		for i := 0; i < len(m.perSec) && i < len(msg.PerThread); i++ {
			delta := float64(msg.PerThread[i]-m.lastCounts[i]) / dt
			m.perSec[i] = delta
			m.lastCounts[i] = msg.PerThread[i]
		}
		m.total = msg.Total
		m.lastTime = now
		return m, listenStats(m.cfg.StatsCh)

	case statsClosedMsg:
		m.statsOpen = false
		// no resubscribe
		return m, nil

	case resultMsg:
		if msg.Found {
			m.found = true
			m.password = msg.Password
			return m, tea.Quit
		}
		// not found finalization is handled when channels close and program terminates externally
		return m, listenResult(m.cfg.ResultCh)

	case resultClosedMsg:
		m.resultOpen = false
		// If both channels closed, we can quit
		if !m.statsOpen {
			return m, tea.Quit
		}
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ZIP Password Brute Forcer (q to quit)\n")
	fmt.Fprintf(&b, "Workers: %d | Refresh: %s | Elapsed: %s\n",
		len(m.perSec), m.cfg.SampleEvery, time.Since(m.start).Truncate(time.Second))

	// Fixed-width formatting:
	// - Thread label: T%0*d (e.g., T01, T12)
	// - p/s: %7.0f to keep a stable width
	const psWidth = 7

	// Per-thread lines
	b.WriteByte('\n')
	for i, v := range m.perSec {
		fmt.Fprintf(&b, "[T%0*d: %*.0f p/s] ", m.idxWidth, i+1, psWidth, v)
		if (i+1)%4 == 0 {
			b.WriteByte('\n')
		}
	}
	if len(m.perSec)%4 != 0 {
		b.WriteByte('\n')
	}

	var sum float64
	for _, v := range m.perSec {
		sum += v
	}

	// Progress and ETA
	if m.totalComb != nil && sum > 0 {
		attempts := new(big.Int).SetUint64(m.total)
		if attempts.Cmp(m.totalComb) > 0 {
			attempts.Set(m.totalComb)
		}
		percent := percentOf(attempts, m.totalComb)
		bar := progressBar(percent, 40)
		eta := etaString(attempts, m.totalComb, sum)
		fmt.Fprintf(&b, "\nProgress: %s %5.1f%% | ETA: %s\n", bar, percent*100, eta)
	}

	// Totals aligned
	fmt.Fprintf(&b, "\nThroughput total: %*.0f p/s | Attempts total: %d\n", psWidth, sum, m.total)

	if m.found {
		fmt.Fprintf(&b, "\nPassword found: %s\n", m.password)
	}
	return b.String()
}

// computeTotalCombinations = sum_{k=minLen..maxLen} (alpha^k)
func computeTotalCombinations(alpha, minLen, maxLen int) *big.Int {
	if minLen <= 0 {
		minLen = 1
	}
	if maxLen < minLen {
		maxLen = minLen
	}
	A := big.NewInt(int64(alpha))
	total := big.NewInt(0)
	tmp := new(big.Int)
	for k := minLen; k <= maxLen; k++ {
		tmp.Exp(A, big.NewInt(int64(k)), nil)
		total.Add(total, tmp)
	}
	return total
}

// percentOf returns float64 percentage in [0,1]
func percentOf(cur, total *big.Int) float64 {
	if total.Sign() == 0 {
		return 0
	}
	fCur := new(big.Float).SetInt(cur)
	fTot := new(big.Float).SetInt(total)
	r := new(big.Float).Quo(fCur, fTot)
	out, _ := r.Float64()
	if out < 0 {
		return 0
	}
	if out > 1 {
		return 1
	}
	return out
}

// etaString estimates time remaining given attempts so far and current total p/s.
func etaString(cur, total *big.Int, pps float64) string {
	if pps <= 0 {
		return "∞"
	}
	remain := new(big.Int).Sub(total, cur)
	if remain.Sign() <= 0 {
		return "0s"
	}
	// seconds = remain / pps
	fRem := new(big.Float).SetInt(remain)
	fPps := big.NewFloat(pps)
	secsF := new(big.Float).Quo(fRem, fPps)
	secs, _ := secsF.Float64()
	if math.IsInf(secs, 0) || math.IsNaN(secs) {
		return "∞"
	}
	d := time.Duration(secs * float64(time.Second))
	return humanizeDuration(d)
}

func humanizeDuration(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}
	// Round to the nearest second for display
	d = d.Truncate(time.Second)

	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	h := d / time.Hour
	d -= h * time.Hour

	m := d / time.Minute
	d -= m * time.Minute

	s := d / time.Second

	parts := make([]string, 0, 4)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if h > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m > 0 || h > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	parts = append(parts, fmt.Sprintf("%ds", s))

	return strings.Join(parts, " ")
}

// progressBar renders a simple ASCII progress bar of given width for percent in [0,1].
func progressBar(percent float64, width int) string {
	if width <= 0 {
		width = 20
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}
	filled := int(math.Round(percent * float64(width)))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}
