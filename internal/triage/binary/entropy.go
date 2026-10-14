package binary

import (
	"math"
)

// CalculateEntropy computes the Shannon entropy of data, returning a value between 0.0 and 8.0.
// If data is empty, CalculateEntropy returns 0.0.
func CalculateEntropy(data []byte) float64 {
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

	return ent
}
