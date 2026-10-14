package binary

import (
	"crypto/rand"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestCalculateEntropyEmpty(t *testing.T) {
	if got := CalculateEntropy(nil); got != 0.0 {
		t.Fatalf("expected 0.0 for nil slice, got %f", got)
	}
	if got := CalculateEntropy([]byte{}); got != 0.0 {
		t.Fatalf("expected 0.0 for empty slice, got %f", got)
	}
}

func TestCalculateEntropyHomogeneous(t *testing.T) {
	cases := [][]byte{
		make([]byte, 100),
		[]byte("AAAAAAAAAAAAAAAAAAAA"),
		{0xff, 0xff, 0xff, 0xff},
	}

	for _, data := range cases {
		if got := CalculateEntropy(data); got != 0.0 {
			t.Fatalf("expected 0.0 for homogeneous data, got %f", got)
		}
	}
}

func TestCalculateEntropyEquiprobable(t *testing.T) {
	const epsilon = 1e-9

	twoSymbols := make([]byte, 100)
	for i := range twoSymbols {
		if i%2 == 0 {
			twoSymbols[i] = 1
		} else {
			twoSymbols[i] = 2
		}
	}
	if got := CalculateEntropy(twoSymbols); math.Abs(got-1.0) > epsilon {
		t.Fatalf("expected 1.0 for 2 equiprobable symbols, got %f", got)
	}

	fourSymbols := make([]byte, 200)
	for i := range fourSymbols {
		fourSymbols[i] = byte(i % 4)
	}
	if got := CalculateEntropy(fourSymbols); math.Abs(got-2.0) > epsilon {
		t.Fatalf("expected 2.0 for 4 equiprobable symbols, got %f", got)
	}

	all256 := make([]byte, 256)
	for i := 0; i < 256; i++ {
		all256[i] = byte(i)
	}
	if got := CalculateEntropy(all256); math.Abs(got-8.0) > epsilon {
		t.Fatalf("expected 8.0 for 256 equiprobable symbols, got %f", got)
	}
}

func TestCalculateEntropyNaturalText(t *testing.T) {
	text := []byte("The quick brown fox jumps over the lazy dog. A swift movement in user space isolation.")
	ent := CalculateEntropy(text)
	if ent < 3.5 || ent > 5.5 {
		t.Fatalf("expected natural text entropy to be between 3.5 and 5.5, got %f", ent)
	}
}

func TestCalculateEntropyRandomData(t *testing.T) {
	buf := make([]byte, 65536)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	ent := CalculateEntropy(buf)
	if ent < 7.9 || ent > 8.0 {
		t.Fatalf("expected random buffer entropy to be near 8.0 (> 7.9), got %f", ent)
	}
}

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

			ent := CalculateEntropy(data)
			if ent < tt.minEntropy || ent > tt.maxEntropy {
				t.Errorf("CalculateEntropy(%s) = %.4f, want range [%.2f, %.2f]", tt.file, ent, tt.minEntropy, tt.maxEntropy)
			}
		})
	}
}
