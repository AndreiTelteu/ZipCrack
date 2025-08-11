package cracker

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	yzip "github.com/yeka/zip"
)

// ZipChecker holds immutable ZIP bytes and the chosen target index (smallest encrypted file).
// Each worker must derive its own reader/file from the bytes to avoid shared mutation and contention.
type ZipChecker struct {
	zipBytes    []byte
	targetIndex int
}

// ZipWorker is a per-goroutine handle with its own File instance.
type ZipWorker struct {
	file *yzip.File
}

// NewZipChecker constructs a checker from in-memory ZIP bytes.
// It scans entries once to choose the smallest encrypted regular file as the target.
func NewZipChecker(zipBytes []byte) (*ZipChecker, error) {
	br := bytes.NewReader(zipBytes)
	zr, err := yzip.NewReader(br, int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}
	if len(zr.File) == 0 {
		return nil, errors.New("zip has no entries")
	}
	target := -1
	var targetSize uint64 = ^uint64(0) // max

	for i := range zr.File {
		f := zr.File[i]
		// skip directories
		if f.FileInfo().IsDir() {
			continue
		}
		// Require encrypted entries only
		if !f.IsEncrypted() {
			continue
		}
		// Choose the smallest encrypted file to reduce per-attempt cost
		sz := uint64(f.UncompressedSize64)
		if sz < targetSize {
			target = i
			targetSize = sz
		}
	}
	if target == -1 {
		return nil, errors.New("zip has no encrypted files to crack")
	}
	return &ZipChecker{
		zipBytes:    zipBytes,
		targetIndex: target,
	}, nil
}

// NewWorker creates a per-goroutine worker with its own reader and file instance.
// This avoids concurrent SetPassword/Open on shared *zip.File which is not thread-safe.
func (z *ZipChecker) NewWorker() (*ZipWorker, error) {
	br := bytes.NewReader(z.zipBytes)
	zr, err := yzip.NewReader(br, int64(len(z.zipBytes)))
	if err != nil {
		return nil, err
	}
	if z.targetIndex < 0 || z.targetIndex >= len(zr.File) {
		return nil, errors.New("invalid target index")
	}
	return &ZipWorker{file: zr.File[z.targetIndex]}, nil
}

// Try attempts to open the worker's target file using the provided password.
// Reads a single byte to exercise decryption quickly. Returns true when password is correct.
func (w *ZipWorker) Try(password string) bool {
	f := w.file
	f.SetPassword(password)

	rc, err := f.Open()
	if err != nil {
		// Wrong password or open failure (most common on incorrect AES password).
		return false
	}
	// Force full read to EOF. For AES-encrypted entries, MAC/auth verification
	// typically occurs only after full stream consumption or on Close.
	_, copyErr := io.Copy(ioutil.Discard, rc)
	closeErr := rc.Close()

	// Any error during stream read or close indicates wrong password.
	return copyErr == nil && closeErr == nil
}

// Optional: full verification variant (unused), kept for reference.
// This forces full read to EOF, ensuring CRC/MAC verification, but is much slower.
func (w *ZipWorker) tryFull(password string) bool {
	f := w.file
	f.SetPassword(password)
	rc, err := f.Open()
	if err != nil {
		return false
	}
	defer rc.Close()
	_, err = io.Copy(ioutil.Discard, rc)
	return err == nil
}
