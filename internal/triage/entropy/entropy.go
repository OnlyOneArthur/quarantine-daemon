package entropy

import (
	"math"
)

// Calculate computes the Shannon entropy of data, returning a value between 0.0 and 8.0.
// If data is empty, Calculate returns 0.0.
func Calculate(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0.0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(n)
	var ent float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			ent -= p * math.Log2(p)
		}
	}

	// Clamp to theoretical bounds [0.0, 8.0] to guard against floating-point inaccuracies
	if ent < 0.0 {
		return 0.0
	}
	if ent > 8.0 {
		return 8.0
	}

	return ent
}
