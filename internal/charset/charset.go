package charset

import "unicode"

// Letters returns ASCII letters a-zA-Z.
func Letters() []rune {
	letters := make([]rune, 0, 52)
	for r := 'a'; r <= 'z'; r++ {
		letters = append(letters, r)
	}
	for r := 'A'; r <= 'Z'; r++ {
		letters = append(letters, r)
	}
	return letters
}

// Digits returns ASCII digits 0-9.
func Digits() []rune {
	d := make([]rune, 0, 10)
	for r := '0'; r <= '9'; r++ {
		d = append(d, r)
	}
	return d
}

// SpecialCommon returns a small, common set of special characters.
func SpecialCommon() []rune {
	const s = "!@#$%^&*_-"
	return []rune(s)
}

// SpecialAll returns a broad set of ASCII punctuation characters.
func SpecialAll() []rune {
	out := make([]rune, 0, 32)
	for r := rune(33); r <= rune(126); r++ { // printable ASCII
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' {
			continue
		}
		out = append(out, r)
	}
	return out
}

// Combine merges multiple rune slices into one, de-duplicated, preserving order.
func Combine(sets ...[]rune) []rune {
	seen := make(map[rune]bool, 256)
	out := make([]rune, 0, 256)
	for _, s := range sets {
		for _, r := range s {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}
