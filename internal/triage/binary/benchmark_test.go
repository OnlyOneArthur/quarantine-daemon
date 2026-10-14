// Package binary holds the triage benchmark suite.
package binary

import (
	"encoding/binary"
	mathrand "math/rand"
	"testing"

	"github.com/OnlyOneArthur/quarantine-daemon/internal/config"
)

func BenchmarkTriageSyntheticELF32MiB(b *testing.B) {
	data := make([]byte, 32<<20)
	mathrand.New(mathrand.NewSource(1)).Read(data)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], 0x3e)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[24:32], 0x400000)
	cfg := config.DefaultConfig()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := TriageBinary(data, "fixture", cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkForEachIPv4_32MiB(b *testing.B) {
	data := make([]byte, 32<<20)
	mathrand.New(mathrand.NewSource(1)).Read(data)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		count := 0
		forEachIPv4(data, 100, func(m []byte) { count++ })
	}
}

func BenchmarkScanRawIOCs_32MiB(b *testing.B) {
	data := make([]byte, 32<<20)
	mathrand.New(mathrand.NewSource(1)).Read(data)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanRawIOCs(data)
	}
}
