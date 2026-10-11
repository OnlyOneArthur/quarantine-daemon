package entropy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEntropyFixtures validates Shannon entropy calculations against
// synthetic fixtures in testdata/entropy.
func TestEntropyFixtures(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		minEntropy float64
		maxEntropy float64
	}{
		{
			name:       "High entropy random binary sample",
			file:       "high_entropy.bin",
			minEntropy: 7.5,
			maxEntropy: 8.0,
		},
		{
			name:       "Low entropy homogeneous byte sequence",
			file:       "low_entropy.bin",
			minEntropy: 0.0,
			maxEntropy: 0.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "testdata", "entropy", tt.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture %s: %v", path, err)
			}

			ent := Calculate(data)
			if ent < tt.minEntropy || ent > tt.maxEntropy {
				t.Errorf("Calculate(%s) = %.4f, want range [%.2f, %.2f]", tt.file, ent, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}
