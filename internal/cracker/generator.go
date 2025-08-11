package cracker

import (
	"math/rand"
)

type batch []string

// generateBatch creates a slice of random password candidates with lengths in [minLen, maxLen].
func generateBatch(alphabet []rune, minLen, maxLen, batchSize int, rng *rand.Rand) batch {
	if batchSize <= 0 {
		batchSize = 1
	}
	out := make([]string, batchSize)
	al := len(alphabet)
	if al == 0 {
		return out
	}
	for i := 0; i < batchSize; i++ {
		l := minLen
		if maxLen > minLen {
			l += rng.Intn(maxLen - minLen + 1)
		}
		b := make([]rune, l)
		for j := 0; j < l; j++ {
			b[j] = alphabet[rng.Intn(al)]
		}
		out[i] = string(b)
	}
	return out
}
