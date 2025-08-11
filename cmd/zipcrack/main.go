package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"zipcrack/internal/charset"
	"zipcrack/internal/cracker"
	"zipcrack/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
)

func promptString(r *bufio.Reader, label, def string) string {
	fmt.Printf("%s [%s]: ", label, def)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptYesNo(r *bufio.Reader, label string, def bool) bool {
	defStr := "y"
	if !def {
		defStr = "n"
	}
	fmt.Printf("%s (y/n) [%s]: ", label, defStr)
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return def
	}
	return line == "y" || line == "yes"
}

func promptInt(r *bufio.Reader, label string, def int) int {
	for {
		fmt.Printf("%s [%d]: ", label, def)
		line, _ := r.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			return def
		}
		v, err := strconv.Atoi(line)
		if err != nil || v < 0 {
			fmt.Println("Please enter a non-negative integer.")
			continue
		}
		return v
	}
}

func main() {
	_ = rand.New(rand.NewSource(time.Now().UnixNano()))
	reader := bufio.NewReader(os.Stdin)

	// Defaults from user confirmation
	defaultZip := "/home/andrei/target.zip"
	defaultBatch := 8192
	defaultCPUs := runtime.NumCPU()

	zipPath := promptString(reader, "ZIP file path", defaultZip)

	// Character set selection (allow combinations)
	useLetters := promptYesNo(reader, "Use letters (a-zA-Z)?", true)
	useNumbers := promptYesNo(reader, "Use numbers (0-9)?", true)
	useSpecialCommon := promptYesNo(reader, "Use special common (!@#$%^&*_-)?", true)
	useSpecialAll := promptYesNo(reader, "Use special ALL (ASCII punctuation)?", false)

	if !useLetters && !useNumbers && !useSpecialCommon && !useSpecialAll {
		fmt.Println("No character sets selected, enabling letters by default.")
		useLetters = true
	}

	minLen := promptInt(reader, "Minimum password length", 1)
	maxLen := promptInt(reader, "Maximum password length", 8)
	if maxLen < minLen {
		fmt.Printf("Max length < min length, adjusting max=%d\n", minLen)
		maxLen = minLen
	}

	workers := promptInt(reader, fmt.Sprintf("Threads (logical CPUs=%d)", defaultCPUs), defaultCPUs)
	if workers <= 0 {
		workers = 1
	}
	batchSize := promptInt(reader, "Batch size", defaultBatch)
	if batchSize <= 0 {
		batchSize = defaultBatch
	}

	// Build charset
	var sets [][]rune
	if useLetters {
		sets = append(sets, charset.Letters())
	}
	if useNumbers {
		sets = append(sets, charset.Digits())
	}
	if useSpecialCommon {
		sets = append(sets, charset.SpecialCommon())
	}
	if useSpecialAll {
		sets = append(sets, charset.SpecialAll())
	}
	alphabet := charset.Combine(sets...)

	// Load ZIP file into memory
	zipBytes, err := os.ReadFile(zipPath)
	if err != nil {
		log.Fatalf("failed to read zip: %v", err)
	}

	// Prepare cracking runner
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := cracker.Config{
		ZipBytes:      zipBytes,
		Alphabet:      alphabet,
		MinLen:        minLen,
		MaxLen:        maxLen,
		Workers:       workers,
		BatchSize:     batchSize,
		ReportEvery:   2 * time.Second,
		FoundCallback: func(pw string) { cancel() },
	}
	run, err := cracker.NewRunner(cfg)
	if err != nil {
		log.Fatalf("failed to init runner: %v", err)
	}

	// TUI model
	model := tui.NewModel(tui.Config{
		Workers:     workers,
		SampleEvery: cfg.ReportEvery,
		StatsCh:     run.StatsCh(),
		ResultCh:    run.ResultCh(),
		Stop:        cancel,
	})

	// Start cracking in background
	go func() {
		if err := run.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("runner error: %v", err)
			cancel()
		}
	}()

	// Start TUI
	if _, err := tea.NewProgram(model).Run(); err != nil {
		log.Fatalf("tui error: %v", err)
	}

	// After TUI exits, print result if found
	res := run.GetResult()
	if res.Found {
		fmt.Printf("\nPassword found: %s\n", res.Password)
	} else {
		fmt.Println("\nPassword not found or operation cancelled.")
	}
}
