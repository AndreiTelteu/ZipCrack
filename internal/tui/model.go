package tui

import (
	"fmt"
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

	start time.Time
}

func NewModel(cfg Config) model {
	return model{
		cfg:        cfg,
		perSec:     make([]float64, cfg.Workers),
		lastCounts: make([]uint64, cfg.Workers),
		statsOpen:  true,
		resultOpen: true,
		start:      time.Now(),
	}
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
	fmt.Fprintf(&b, "Workers: %d | Refresh: %s | Elapsed: %s\n\n",
		len(m.perSec), m.cfg.SampleEvery, time.Since(m.start).Truncate(time.Second))

	// Per-thread lines
	for i, v := range m.perSec {
		fmt.Fprintf(&b, "[T%d: %.0f p/s] ", i+1, v)
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
	fmt.Fprintf(&b, "\nThroughput total: %.0f p/s | Attempts total: %d\n", sum, m.total)

	if m.found {
		fmt.Fprintf(&b, "\nPassword found: %s\n", m.password)
	}
	return b.String()
}
