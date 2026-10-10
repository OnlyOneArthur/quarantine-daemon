package entropy

import (
	"crypto/rand"
	"math"
	"testing"
)

func TestCalculateEmpty(t *testing.T) {
	if got := Calculate(nil); got != 0.0 {
		t.Fatalf("expected 0.0 for nil slice, got %f", got)
	}
	if got := Calculate([]byte{}); got != 0.0 {
		t.Fatalf("expected 0.0 for empty slice, got %f", got)
	}
}

func TestCalculateHomogeneous(t *testing.T) {
	cases := [][]byte{
		make([]byte, 100),
		[]byte("AAAAAAAAAAAAAAAAAAAA"),
		{0xff, 0xff, 0xff, 0xff},
	}

	for _, data := range cases {
		if got := Calculate(data); got != 0.0 {
			t.Fatalf("expected 0.0 for homogeneous data, got %f", got)
		}
	}
}

func TestCalculateEquiprobable(t *testing.T) {
	const epsilon = 1e-9

	// 2 equiprobable symbols -> -2 * (0.5 * log2(0.5)) = 1.0
	twoSymbols := make([]byte, 100)
	for i := range twoSymbols {
		if i%2 == 0 {
			twoSymbols[i] = 1
		} else {
			twoSymbols[i] = 2
		}
	}
	if got := Calculate(twoSymbols); math.Abs(got-1.0) > epsilon {
		t.Fatalf("expected 1.0 for 2 equiprobable symbols, got %f", got)
	}

	// 4 equiprobable symbols -> -4 * (0.25 * log2(0.25)) = 2.0
	fourSymbols := make([]byte, 200)
	for i := range fourSymbols {
		fourSymbols[i] = byte(i % 4)
	}
	if got := Calculate(fourSymbols); math.Abs(got-2.0) > epsilon {
		t.Fatalf("expected 2.0 for 4 equiprobable symbols, got %f", got)
	}

	// 256 equiprobable symbols (1 of each) -> 8.0
	all256 := make([]byte, 256)
	for i := 0; i < 256; i++ {
		all256[i] = byte(i)
	}
	if got := Calculate(all256); math.Abs(got-8.0) > epsilon {
		t.Fatalf("expected 8.0 for 256 equiprobable symbols, got %f", got)
	}

	// 256 equiprobable symbols repeated (4 of each = 1024 bytes) -> 8.0
	repeated256 := make([]byte, 1024)
	for i := 0; i < 1024; i++ {
		repeated256[i] = byte(i % 256)
	}
	if got := Calculate(repeated256); math.Abs(got-8.0) > epsilon {
		t.Fatalf("expected 8.0 for repeated 256 equiprobable symbols, got %f", got)
	}
}

func TestCalculateNaturalText(t *testing.T) {
	text := []byte("The quick brown fox jumps over the lazy dog. A swift movement in user space isolation.")
	ent := Calculate(text)
	if ent < 3.5 || ent > 5.5 {
		t.Fatalf("expected natural text entropy to be between 3.5 and 5.5, got %f", ent)
	}
}

func TestCalculateRandomData(t *testing.T) {
	buf := make([]byte, 65536)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}

	ent := Calculate(buf)
	if ent < 7.9 || ent > 8.0 {
		t.Fatalf("expected random buffer entropy to be near 8.0 (> 7.9), got %f", ent)
	}
}
