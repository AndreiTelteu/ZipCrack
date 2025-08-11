package cracker

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"

	yzip "github.com/yeka/zip"
)

// ZipChecker holds parsed ZIP file entries and indices of encrypted files to test passwords against.
type ZipChecker struct {
	files          []*yzip.File
	encryptedIndex []int
}

// NewZipChecker constructs a checker from in-memory ZIP bytes.
// It collects all encrypted regular file entries as targets; returns error if none.
func NewZipChecker(zipBytes []byte) (*ZipChecker, error) {
	br := bytes.NewReader(zipBytes)
	zr, err := yzip.NewReader(br, int64(len(zipBytes)))
	if err != nil {
		return nil, err
	}
	if len(zr.File) == 0 {
		return nil, errors.New("zip has no entries")
	}
	files := make([]*yzip.File, 0, len(zr.File))
	encIdx := make([]int, 0, len(zr.File))
	for i := range zr.File {
		f := zr.File[i]
		files = append(files, f)
		// skip directories
		if f.FileInfo().IsDir() {
			continue
		}
		// Require encrypted entries only
		// yeka/zip exposes IsEncrypted on File
		if f.IsEncrypted() {
			encIdx = append(encIdx, i)
		}
	}
	if len(encIdx) == 0 {
		return nil, errors.New("zip has no encrypted files to crack")
	}
	return &ZipChecker{
		files:          files,
		encryptedIndex: encIdx,
	}, nil
}

// Try attempts to open each encrypted target file using the provided password.
// Returns true when the password is correct for any encrypted file, false otherwise.
// It forces full read to EOF to trigger decryption/CRC checks.
func (z *ZipChecker) Try(password string) bool {
	for _, idx := range z.encryptedIndex {
		f := z.files[idx]
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			// Wrong password or open failure; try next
			continue
		}
		// Ensure full read to validate decryption/CRC
		_, copyErr := io.Copy(ioutil.Discard, rc)
		rc.Close()
		if copyErr == nil {
			// Successful full read => correct password
			return true
		}
	}
	return false
}
