package vmware

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestDiskCapacityReadsVirtualSizeFromSparseHeader(t *testing.T) {
	for _, version := range []uint32{1, 2, 3} {
		var header [512]byte
		binary.LittleEndian.PutUint32(header[:4], 0x564d444b)
		binary.LittleEndian.PutUint32(header[4:8], version)
		// Exercise the high 32 bits and a fraction which must not round upward.
		binary.LittleEndian.PutUint64(header[12:20], 4096*(1<<21)+(1<<20))
		path := filepath.Join(t.TempDir(), "disk.vmdk")
		if err := os.WriteFile(path, header[:], 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := DiskCapacityGB(path); err != nil || got != 4096 {
			t.Fatalf("version %d: capacity = %d, error = %v", version, got, err)
		}
	}
}

func TestDiskCapacityRejectsInvalidOrMissingHeaders(t *testing.T) {
	for _, which := range []string{"missing", "truncated", "magic", "version", "zero"} {
		t.Run(which, func(t *testing.T) {
			var header [512]byte
			binary.LittleEndian.PutUint32(header[:4], 0x564d444b)
			binary.LittleEndian.PutUint32(header[4:8], 1)
			binary.LittleEndian.PutUint64(header[12:20], 20*(1<<21))
			data := header[:]
			switch which {
			case "truncated":
				data = header[:20]
			case "magic":
				header[0] = 0
			case "version":
				binary.LittleEndian.PutUint32(header[4:8], 99)
			case "zero":
				binary.LittleEndian.PutUint64(header[12:20], 0)
			}
			path := filepath.Join(t.TempDir(), "disk.vmdk")
			if which != "missing" {
				if err := os.WriteFile(path, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := DiskCapacityGB(path); err == nil {
				t.Fatal("invalid disk reported a capacity")
			}
		})
	}
}
