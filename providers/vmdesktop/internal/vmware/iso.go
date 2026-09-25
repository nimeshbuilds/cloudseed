package vmware

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// A minimal ISO 9660 writer for the cloud-init NoCloud seed: one root directory holding a few small files. It exists
// so the seed can be built on hosts without hdiutil/genisoimage/mkisofs/xorriso (every Windows host, many Linux ones).
//
// File identifiers are written as upper-case "NAME.;1"; Linux's isofs (default map=normal, which is how cloud-init
// mounts the seed) presents them as the lower-case "name" cloud-init looks for (user-data, meta-data, network-config).

const isoSector = 2048

func isoBoth32(b []byte, v uint32) {
	binary.LittleEndian.PutUint32(b[0:4], v)
	binary.BigEndian.PutUint32(b[4:8], v)
}

func isoBoth16(b []byte, v uint16) {
	binary.LittleEndian.PutUint16(b[0:2], v)
	binary.BigEndian.PutUint16(b[2:4], v)
}

func isoRecordDate(b []byte, t time.Time) {
	b[0] = byte(t.Year() - 1900)
	b[1] = byte(t.Month())
	b[2] = byte(t.Day())
	b[3] = byte(t.Hour())
	b[4] = byte(t.Minute())
	b[5] = byte(t.Second())
	b[6] = 0 // UTC
}

func isoVolumeDate(b []byte, t time.Time) {
	copy(b[0:16], fmt.Sprintf("%04d%02d%02d%02d%02d%02d00", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second()))
	b[16] = 0 // UTC
}

func isoPad(b []byte, s string) {
	for i := range b {
		b[i] = ' '
	}
	copy(b, s)
}

// isoDirRecord builds one directory record; records are padded to an even length.
func isoDirRecord(id []byte, extent, size uint32, dir bool, t time.Time) []byte {
	n := 33 + len(id)
	if n%2 == 1 {
		n++
	}
	r := make([]byte, n)
	r[0] = byte(n)
	isoBoth32(r[2:10], extent)
	isoBoth32(r[10:18], size)
	isoRecordDate(r[18:25], t)
	if dir {
		r[25] = 0x02
	}
	isoBoth16(r[28:32], 1)
	r[32] = byte(len(id))
	copy(r[33:], id)
	return r
}

// isoFileID turns "user-data" into the ISO 9660 identifier "USER-DATA.;1".
func isoFileID(name string) (string, error) {
	up := strings.ToUpper(name)
	if up == "" || len(up) > 30 {
		return "", fmt.Errorf("unsupported file name %q", name)
	}
	for _, c := range up {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", fmt.Errorf("unsupported character %q in file name %q", c, name)
		}
	}
	return up + ".;1", nil
}

// BuildISO9660 returns an ISO 9660 image with the given volume label and files (all in the root directory).
func BuildISO9660(volumeID string, files map[string][]byte) ([]byte, error) {
	if len(volumeID) > 32 {
		return nil, fmt.Errorf("volume id %q is longer than 32 characters", volumeID)
	}
	type entry struct {
		id     string
		data   []byte
		extent uint32
	}
	var entries []entry
	for name, data := range files {
		id, err := isoFileID(name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{id: id, data: data})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })

	now := time.Now().UTC()
	const (
		pvdSector  = 16
		termSector = 17
		lPathTable = 18
		mPathTable = 19
		rootSector = 20
	)
	next := uint32(rootSector + 1)
	for i := range entries {
		entries[i].extent = next
		next += uint32((len(entries[i].data) + isoSector - 1) / isoSector)
	}
	total := next

	// Root directory: ".", "..", then the files (sorted); everything must fit its single sector.
	root := isoDirRecord([]byte{0}, rootSector, isoSector, true, now)
	dirData := append([]byte{}, root...)
	dirData = append(dirData, isoDirRecord([]byte{1}, rootSector, isoSector, true, now)...)
	for _, e := range entries {
		dirData = append(dirData, isoDirRecord([]byte(e.id), e.extent, uint32(len(e.data)), false, now)...)
	}
	if len(dirData) > isoSector {
		return nil, fmt.Errorf("too many files for the root directory")
	}

	img := make([]byte, int(total)*isoSector)

	pvd := img[pvdSector*isoSector : (pvdSector+1)*isoSector]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	isoPad(pvd[8:40], "")
	isoPad(pvd[40:72], volumeID)
	isoBoth32(pvd[80:88], total)
	isoBoth16(pvd[120:124], 1)
	isoBoth16(pvd[124:128], 1)
	isoBoth16(pvd[128:132], isoSector)
	isoBoth32(pvd[132:140], 10) // path table: the root entry only
	binary.LittleEndian.PutUint32(pvd[140:144], lPathTable)
	binary.BigEndian.PutUint32(pvd[148:152], mPathTable)
	copy(pvd[156:190], root)
	isoPad(pvd[190:318], "")
	isoPad(pvd[318:446], "")
	isoPad(pvd[446:574], "")
	isoPad(pvd[574:702], "CLOUDSEED")
	isoPad(pvd[702:739], "")
	isoPad(pvd[739:776], "")
	isoPad(pvd[776:813], "")
	isoVolumeDate(pvd[813:830], now)
	isoVolumeDate(pvd[830:847], now)
	copy(pvd[847:863], "0000000000000000")
	copy(pvd[864:880], "0000000000000000")
	pvd[881] = 1

	term := img[termSector*isoSector:]
	term[0] = 255
	copy(term[1:6], "CD001")
	term[6] = 1

	lpt := img[lPathTable*isoSector:]
	lpt[0] = 1
	binary.LittleEndian.PutUint32(lpt[2:6], rootSector)
	binary.LittleEndian.PutUint16(lpt[6:8], 1)
	mpt := img[mPathTable*isoSector:]
	mpt[0] = 1
	binary.BigEndian.PutUint32(mpt[2:6], rootSector)
	binary.BigEndian.PutUint16(mpt[6:8], 1)

	copy(img[rootSector*isoSector:], dirData)
	for _, e := range entries {
		copy(img[int(e.extent)*isoSector:], e.data)
	}
	return img, nil
}

// WriteISO9660 writes BuildISO9660's image to path.
func WriteISO9660(path, volumeID string, files map[string][]byte) error {
	img, err := BuildISO9660(volumeID, files)
	if err != nil {
		return err
	}
	return os.WriteFile(path, img, 0o644)
}
