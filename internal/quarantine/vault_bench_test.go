package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

func populateBenchmarkVault(b *testing.B, v *Vault, count int) {
	b.Helper()
	v.SetLimits(1024, 30) // 1GB cap, 30 days retention
	for i := 0; i < count; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("item-%d", i)))
		id := hex.EncodeToString(h[:])
		artPath := v.artifactPath(id)
		if err := os.WriteFile(artPath, []byte("payload"), 0000); err != nil {
			b.Fatalf("write artifact: %v", err)
		}
		meta := &ItemMetadata{
			ID:            id,
			SHA256:        id,
			Size:          7,
			QuarantinedAt: time.Now().UTC().AddDate(0, 0, -i%60), // some expired, some active
		}
		if err := v.writeMeta(meta); err != nil {
			b.Fatalf("write meta: %v", err)
		}
	}
}

func BenchmarkVaultCheckSizeCap(b *testing.B) {
	vaultDir := b.TempDir()
	v, err := New(vaultDir)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	defer v.Close()

	populateBenchmarkVault(b, v, 200)

	testID := hex.EncodeToString(sha256.New().Sum([]byte("new-item")))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.checkSizeCap(testID, 1024); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVaultSweep(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		vaultDir := b.TempDir()
		v, err := New(vaultDir)
		if err != nil {
			b.Fatalf("New: %v", err)
		}
		populateBenchmarkVault(b, v, 200)
		b.StartTimer()

		if err := v.Sweep(); err != nil {
			b.Fatal(err)
		}
		v.Close()
	}
}
