package verifier

import (
	"encoding/binary"
	"errors"
)

// ZipCryptoInfo holds the minimal metadata needed for ZipCrypto header verification on GPU
type ZipCryptoInfo struct {
	// 12-byte encrypted header from the file
	EncryptedHeader [12]byte
	// CRC32 of the uncompressed data
	CRC32 uint32
	// MS-DOS time (used for check byte in some cases)
	ModTime uint16
	// General purpose flag (bit 3 determines check byte method)
	Flag uint16
	// Expected check byte for verification
	CheckByte byte
}

// parseZipHeaders scans the ZIP file and returns ZipCryptoInfo for the smallest encrypted entry
func parseZipHeaders(zipBytes []byte) (*ZipCryptoInfo, error) {
	if len(zipBytes) < 22 {
		return nil, errors.New("zip file too small")
	}

	// Find End of Central Directory record (EOCD)
	eocdOffset := findEOCD(zipBytes)
	if eocdOffset == -1 {
		return nil, errors.New("end of central directory not found")
	}

	// Parse EOCD to get central directory info
	cdOffset := binary.LittleEndian.Uint32(zipBytes[eocdOffset+16:])
	numEntries := binary.LittleEndian.Uint16(zipBytes[eocdOffset+10:])

	if cdOffset >= uint32(len(zipBytes)) {
		return nil, errors.New("invalid central directory offset")
	}

	var bestInfo *ZipCryptoInfo
	var bestSize uint64 = ^uint64(0) // max value

	// Parse central directory entries
	offset := cdOffset
	for i := uint16(0); i < numEntries && offset < uint32(len(zipBytes)-46); i++ {
		// Check central directory file header signature
		if binary.LittleEndian.Uint32(zipBytes[offset:]) != 0x02014b50 {
			return nil, errors.New("invalid central directory entry")
		}

		// Extract fields from central directory entry
		flag := binary.LittleEndian.Uint16(zipBytes[offset+8:])
		method := binary.LittleEndian.Uint16(zipBytes[offset+10:])
		modTime := binary.LittleEndian.Uint16(zipBytes[offset+12:])
		crc32 := binary.LittleEndian.Uint32(zipBytes[offset+16:])
		uncompressedSize := binary.LittleEndian.Uint32(zipBytes[offset+24:])
		fileNameLen := binary.LittleEndian.Uint16(zipBytes[offset+28:])
		extraLen := binary.LittleEndian.Uint16(zipBytes[offset+30:])
		commentLen := binary.LittleEndian.Uint16(zipBytes[offset+32:])
		localHeaderOffset := binary.LittleEndian.Uint32(zipBytes[offset+42:])

		// Skip to next entry
		nextOffset := offset + 46 + uint32(fileNameLen) + uint32(extraLen) + uint32(commentLen)

		// Check if this is an encrypted entry (bit 0 of flag) and uses traditional encryption
		if (flag&0x01) != 0 && method == 0 { // stored with traditional encryption
			// Find the corresponding local file header to get encrypted data
			if localHeaderOffset < uint32(len(zipBytes)-30) {
				info, err := extractZipCryptoInfo(zipBytes, localHeaderOffset, flag, crc32, modTime)
				if err == nil && uint64(uncompressedSize) < bestSize {
					bestInfo = info
					bestSize = uint64(uncompressedSize)
				}
			}
		}

		offset = nextOffset
	}

	if bestInfo == nil {
		return nil, errors.New("no suitable encrypted entries found")
	}

	return bestInfo, nil
}

// findEOCD searches for the End of Central Directory record signature
func findEOCD(zipBytes []byte) int {
	// Search backwards from the end for EOCD signature (0x06054b50)
	for i := len(zipBytes) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(zipBytes[i:]) == 0x06054b50 {
			return i
		}
	}
	return -1
}

// extractZipCryptoInfo extracts the 12-byte encryption header from a local file entry
func extractZipCryptoInfo(zipBytes []byte, localHeaderOffset uint32, flag uint16, crc32 uint32, modTime uint16) (*ZipCryptoInfo, error) {
	if localHeaderOffset+30 > uint32(len(zipBytes)) {
		return nil, errors.New("invalid local header offset")
	}

	// Check local file header signature
	if binary.LittleEndian.Uint32(zipBytes[localHeaderOffset:]) != 0x04034b50 {
		return nil, errors.New("invalid local file header")
	}

	// Get file name and extra field lengths
	fileNameLen := binary.LittleEndian.Uint16(zipBytes[localHeaderOffset+26:])
	extraLen := binary.LittleEndian.Uint16(zipBytes[localHeaderOffset+28:])

	// Calculate start of encrypted data (after local header + filename + extra field)
	encryptedDataOffset := localHeaderOffset + 30 + uint32(fileNameLen) + uint32(extraLen)

	if encryptedDataOffset+12 > uint32(len(zipBytes)) {
		return nil, errors.New("insufficient data for encryption header")
	}

	// Extract 12-byte encryption header
	var header [12]byte
	copy(header[:], zipBytes[encryptedDataOffset:encryptedDataOffset+12])

	// Determine check byte based on general purpose flag bit 3
	var checkByte byte
	if (flag & 0x08) != 0 {
		// Bit 3 set: use MS-DOS time
		checkByte = byte(modTime >> 8)
	} else {
		// Bit 3 clear: use CRC32 high byte
		checkByte = byte(crc32 >> 24)
	}

	return &ZipCryptoInfo{
		EncryptedHeader: header,
		CRC32:           crc32,
		ModTime:         modTime,
		Flag:            flag,
		CheckByte:       checkByte,
	}, nil
}
