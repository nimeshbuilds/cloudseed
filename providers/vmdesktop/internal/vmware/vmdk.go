package vmware

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// DiskCapacityGB reads the capacity of the monolithic sparse VMDKs produced by
// VdiskManager -t 0. Allocated file length is not a sparse disk's virtual size.
// The packed header stores little-endian capacity in 512-byte sectors at offset
// 12: https://github.com/vmware/open-vmdk/blob/master/vmdk/vmware_vmdk.h
// Only whole GiB are reported: rounding up could hide an incomplete expansion.
func DiskCapacityGB(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var header [512]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return 0, fmt.Errorf("reading VMDK header from %s: %w", path, err)
	}
	if binary.LittleEndian.Uint32(header[:4]) != 0x564d444b {
		return 0, fmt.Errorf("%s is not a monolithic sparse VMDK", path)
	}
	version := binary.LittleEndian.Uint32(header[4:8])
	if version < 1 || version > 3 {
		return 0, fmt.Errorf("%s has unsupported sparse VMDK version %d", path, version)
	}
	sectors := binary.LittleEndian.Uint64(header[12:20])
	if sectors == 0 {
		return 0, fmt.Errorf("%s has zero VMDK capacity", path)
	}
	return int64(sectors / (1 << 21)), nil
}
