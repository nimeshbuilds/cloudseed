package vmware

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readISO parses what BuildISO9660 writes: the volume label and the root directory's files.
func readISO(t *testing.T, img []byte) (string, map[string][]byte) {
	t.Helper()
	if len(img)%isoSector != 0 || len(img) < 21*isoSector {
		t.Fatalf("image size %d is not a whole number of sectors past the root", len(img))
	}
	pvd := img[16*isoSector:]
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		t.Fatalf("no primary volume descriptor")
	}
	if term := img[17*isoSector:]; term[0] != 255 || string(term[1:6]) != "CD001" {
		t.Fatalf("no descriptor set terminator")
	}
	if got := binary.LittleEndian.Uint32(pvd[80:84]); int(got)*isoSector != len(img) {
		t.Fatalf("volume space size %d sectors, image has %d", got, len(img)/isoSector)
	}
	if binary.LittleEndian.Uint32(pvd[80:84]) != binary.BigEndian.Uint32(pvd[84:88]) {
		t.Fatalf("both-endian volume size mismatch")
	}
	label := strings.TrimRight(string(pvd[40:72]), " ")
	rootExtent := binary.LittleEndian.Uint32(pvd[156+2 : 156+6])
	dir := img[int(rootExtent)*isoSector : int(rootExtent+1)*isoSector]
	files := map[string][]byte{}
	var order []string
	for off := 0; off < len(dir) && dir[off] != 0; off += int(dir[off]) {
		rec := dir[off : off+int(dir[off])]
		if int(rec[0])%2 != 0 {
			t.Fatalf("odd directory record length %d", rec[0])
		}
		idLen := int(rec[32])
		id := string(rec[33 : 33+idLen])
		if id == "\x00" || id == "\x01" {
			continue
		}
		extent := binary.LittleEndian.Uint32(rec[2:6])
		size := binary.LittleEndian.Uint32(rec[10:14])
		if binary.BigEndian.Uint32(rec[6:10]) != extent || binary.BigEndian.Uint32(rec[14:18]) != size {
			t.Fatalf("both-endian mismatch in record %q", id)
		}
		order = append(order, id)
		// what Linux isofs (map=normal) shows: lower-case, without the ".;1" suffix
		name := strings.ToLower(strings.TrimSuffix(id, ".;1"))
		files[name] = img[int(extent)*isoSector : int(extent)*isoSector+int(size)]
	}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Fatalf("directory records are not sorted: %v", order)
		}
	}
	return label, files
}

func TestBuildISO9660RoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 3*isoSector+17) // spans several sectors
	in := map[string][]byte{
		"user-data":      []byte("#cloud-config\nhostname: t\n"),
		"meta-data":      []byte("instance-id: t\n"),
		"network-config": big,
		"empty":          {},
	}
	img, err := BuildISO9660("cidata", in)
	if err != nil {
		t.Fatal(err)
	}
	label, out := readISO(t, img)
	if label != "cidata" {
		t.Fatalf("label %q", label)
	}
	for name, want := range in {
		if got, ok := out[name]; !ok || !bytes.Equal(got, want) {
			t.Fatalf("%s: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}

func TestBuildISO9660RefusesBadNames(t *testing.T) {
	if _, err := BuildISO9660("cidata", map[string][]byte{"a/b": nil}); err == nil {
		t.Fatal("a name with a slash was accepted")
	}
	if _, err := BuildISO9660(strings.Repeat("v", 33), nil); err == nil {
		t.Fatal("a 33-character volume id was accepted")
	}
}

func TestMakeCidataWithoutHostTools(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no hdiutil / genisoimage / mkisofs / xorriso
	dir := t.TempDir()
	iso, err := MakeCidata(dir, "#cloud-config\n", "instance-id: w1\n", "version: 2\n")
	if err != nil {
		t.Fatal(err)
	}
	if iso != filepath.Join(dir, "cidata.iso") {
		t.Fatalf("iso path %q", iso)
	}
	img, err := os.ReadFile(iso)
	if err != nil {
		t.Fatal(err)
	}
	label, files := readISO(t, img)
	if label != "cidata" || string(files["network-config"]) != "version: 2\n" || string(files["meta-data"]) != "instance-id: w1\n" {
		t.Fatalf("seed without host tools: label %q files %v", label, files)
	}
}

func TestGuestinfoMetadataCarriesNetworkConfig(t *testing.T) {
	nc := "version: 2\nethernets:\n  priv:\n    addresses: [10.0.0.10/24]\n"
	got := GuestinfoMetadata("instance-id: w1\nlocal-hostname: w1", nc)
	want := "instance-id: w1\nlocal-hostname: w1\nnetwork: " + base64.StdEncoding.EncodeToString([]byte(nc)) + "\nnetwork.encoding: base64\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if GuestinfoMetadata("instance-id: x\n", "") != "instance-id: x\n" {
		t.Fatal("metadata changed without a network config")
	}
	own := "instance-id: x\nnetwork:\n  config: disabled\n"
	if GuestinfoMetadata(own, nc) != own {
		t.Fatal("a metadata network key was overwritten")
	}
	j := GuestinfoMetadata(`{"instance-id": "x"}`, nc)
	if !strings.Contains(j, `"network.encoding":"base64"`) || !strings.Contains(j, `"instance-id":"x"`) {
		t.Fatalf("json metadata: %s", j)
	}
	spec := VMSpec{Name: "w1", UserData: "#cloud-config\n", MetaData: "instance-id: w1\n", NetworkConfig: nc}
	vmx := spec.Render()
	enc := base64.StdEncoding.EncodeToString([]byte(GuestinfoMetadata(spec.MetaData, nc)))
	if !strings.Contains(vmx, `guestinfo.metadata = "`+enc+`"`) {
		t.Fatalf("vmx guestinfo.metadata does not carry the network config:\n%s", vmx)
	}
}
