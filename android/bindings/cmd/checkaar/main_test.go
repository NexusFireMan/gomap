package main

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func fixtureELF(machine elf.Machine, alignment uint64) []byte {
	data := make([]byte, 120)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], uint16(elf.ET_DYN))
	binary.LittleEndian.PutUint16(data[18:], uint16(machine))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], 1)
	binary.LittleEndian.PutUint32(data[64:], uint32(elf.PT_LOAD))
	binary.LittleEndian.PutUint64(data[96:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[104:], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[112:], alignment)
	return data
}

func fixtureZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestArchiveCompatibilityGates(t *testing.T) {
	for _, name := range []string{"valid", "wrong minimum", "maximum SDK", "missing ABI", "wrong machine", "4 KB alignment", "missing Java", "invalid manifest", "unexpected ABI", "duplicate SDK element"} {
		t.Run(name, func(t *testing.T) {
			manifest := []byte(`<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:minSdkVersion="31"/></manifest>`)
			classes := map[string][]byte{"com/nexusfireman/gomap/mobile/Mobile.class": {}, "com/nexusfireman/gomap/mobile/Session.class": {}, "go/Seq.class": {}}
			entries := map[string][]byte{"AndroidManifest.xml": manifest, "jni/arm64-v8a/libgojni.so": fixtureELF(elf.EM_AARCH64, pageSize), "jni/x86_64/libgojni.so": fixtureELF(elf.EM_X86_64, pageSize)}
			switch name {
			case "wrong minimum":
				entries["AndroidManifest.xml"] = bytes.ReplaceAll(manifest, []byte(`"31"`), []byte(`"33"`))
			case "maximum SDK":
				entries["AndroidManifest.xml"] = bytes.ReplaceAll(manifest, []byte(`"31"`), []byte(`"31" android:maxSdkVersion="36"`))
			case "missing ABI":
				delete(entries, "jni/x86_64/libgojni.so")
			case "wrong machine":
				entries["jni/arm64-v8a/libgojni.so"] = fixtureELF(elf.EM_X86_64, pageSize)
			case "4 KB alignment":
				entries["jni/arm64-v8a/libgojni.so"] = fixtureELF(elf.EM_AARCH64, 4096)
			case "missing Java":
				delete(classes, "go/Seq.class")
			case "invalid manifest":
				entries["AndroidManifest.xml"] = []byte("invalid")
			case "unexpected ABI":
				entries["jni/armeabi-v7a/libgojni.so"] = fixtureELF(elf.EM_AARCH64, pageSize)
			case "duplicate SDK element":
				entries["AndroidManifest.xml"] = []byte(`<manifest><uses-sdk/><uses-sdk/></manifest>`)
			}
			entries["classes.jar"] = fixtureZip(t, classes)
			path := filepath.Join(t.TempDir(), "fixture.aar")
			if err := os.WriteFile(path, fixtureZip(t, entries), 0600); err != nil {
				t.Fatal(err)
			}
			err := checkArchive(path)
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}

func TestELFRejectsMalformedData(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("not ELF"), fixtureELF(elf.EM_ARM, pageSize)} {
		if err := checkELF(data, elf.EM_AARCH64); err == nil {
			t.Fatal("accepted invalid ELF")
		}
	}
	data := fixtureELF(elf.EM_AARCH64, pageSize)
	binary.LittleEndian.PutUint16(data[56:], 0)
	if err := checkELF(data, elf.EM_AARCH64); err == nil {
		t.Fatal("accepted ELF without LOAD segments")
	}
}

func TestMissingArchiveEntry(t *testing.T) {
	if _, err := readEntry(nil, 10); err == nil {
		t.Fatal("accepted missing entry")
	}
	if err := checkArchive(filepath.Join(t.TempDir(), "missing.aar")); err == nil {
		t.Fatal("accepted missing archive")
	}
}
