package verifier

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	yzip "github.com/yeka/zip"
)

// Worker performs batch verification against a specific target entry of a ZIP archive.
// BatchVerify returns:
// - matchIdx: index into the provided batch for the first matching password, or -1 if none matched
// - attempts: number of attempts performed (typically len(batch))
type Worker interface {
	BatchVerify(batch []string) (matchIdx int, attempts int)
	Close()
}

// Verifier constructs a per-goroutine Worker bound to a specific ZIP archive bytes buffer.
type Verifier interface {
	NewWorker(zipBytes []byte) (Worker, error)
}

// NewCPU returns a CPU-based verifier backend.
// This implementation directly uses yeka/zip per attempt for correctness and portability.
func NewCPU() Verifier {
	return &cpuVerifier{}
}

// NewVulkan is implemented in vulkan.go

/*
CPU implementation (portable fallback)

Notes:
- For correctness and to avoid races inside the ZIP reader, we recreate a zip.NewReader
  for each attempt (password). This is slower but simple and thread-safe.
- We scan once in NewWorker to determine the smallest encrypted regular file index to target.
- The verification method mirrors the logic used in the CPU path:
  SetPassword, Open, copy to EOF (to force MAC/CRC verification), and check errors.
*/

type cpuVerifier struct{}

// cpuWorker holds immutable zip bytes and the chosen target index (smallest encrypted file).
type cpuWorker struct {
	zipBytes    []byte
	targetIndex int
}

func (v *cpuVerifier) NewWorker(zipBytes []byte) (Worker, error) {
	if len(zipBytes) == 0 {
		return nil, errors.New("empty zip bytes")
	}
	target, err := findSmallestEncryptedIndex(zipBytes)
	if err != nil {
		return nil, err
	}
	return &cpuWorker{
		zipBytes:    zipBytes,
		targetIndex: target,
	}, nil
}

func (w *cpuWorker) Close() {}

// BatchVerify tries all passwords in the batch and returns the index of the first match (or -1).
func (w *cpuWorker) BatchVerify(batch []string) (int, int) {
	if len(batch) == 0 {
		return -1, 0
	}
	for i, pw := range batch {
		if w.try(pw) {
			return i, i + 1
		}
	}
	return -1, len(batch)
}

// try performs a single password attempt by opening a fresh reader and reading the target entry to EOF.
func (w *cpuWorker) try(password string) bool {
	br := bytes.NewReader(w.zipBytes)
	zr, err := yzip.NewReader(br, int64(len(w.zipBytes)))
	if err != nil {
		return false
	}
	if w.targetIndex < 0 || w.targetIndex >= len(zr.File) {
		return false
	}
	f := zr.File[w.targetIndex]
	f.SetPassword(password)

	rc, err := f.Open()
	if err != nil {
		// Wrong password or open failure.
		return false
	}
	_, copyErr := io.Copy(ioutil.Discard, rc)
	closeErr := rc.Close()
	return copyErr == nil && closeErr == nil
}

// findSmallestEncryptedIndex scans the entries and returns the index of the smallest encrypted regular file.
func findSmallestEncryptedIndex(zipBytes []byte) (int, error) {
	br := bytes.NewReader(zipBytes)
	zr, err := yzip.NewReader(br, int64(len(zipBytes)))
	if err != nil {
		return -1, err
	}
	if len(zr.File) == 0 {
		return -1, errors.New("zip has no entries")
	}
	target := -1
	var targetSize uint64 = ^uint64(0)
	for i := range zr.File {
		f := zr.File[i]
		if f.FileInfo().IsDir() {
			continue
		}
		if !f.IsEncrypted() {
			continue
		}
		sz := uint64(f.UncompressedSize64)
		if sz < targetSize {
			target = i
			targetSize = sz
		}
	}
	if target == -1 {
		return -1, errors.New("zip has no encrypted files to crack")
	}
	return target, nil
}
