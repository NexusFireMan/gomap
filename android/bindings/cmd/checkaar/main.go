// Command checkaar validates static Android compatibility gates, not runtime support.
package main

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const pageSize = 16 * 1024

func main() {
	nativeAPK := len(os.Args) == 3 && os.Args[1] == "--native-apk"
	if len(os.Args) != 2 && !nativeAPK {
		fmt.Fprintln(os.Stderr, "usage: checkaar [--native-apk] path/to/archive")
		os.Exit(1)
	}
	path := os.Args[len(os.Args)-1]
	check := checkArchive
	if nativeAPK {
		check = checkNativeAPK
	}
	if err := check(path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if nativeAPK {
		fmt.Println("APK native checks passed: ARM64/x86_64, Go JNI present, all native LOAD segments 16 KB aligned. Manifest, signing and runtime require separate checks.")
		return
	}
	fmt.Println("AAR static checks passed: minSdk=31, no maxSdk, ARM64/x86_64, 16 KB ELF alignment, Java classes present. Device execution is not verified.")
}

func checkNativeAPK(path string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	machines := map[string]elf.Machine{"arm64-v8a": elf.EM_AARCH64, "x86_64": elf.EM_X86_64}
	seen := make(map[string]bool)
	for _, f := range r.File {
		if seen[f.Name] {
			return fmt.Errorf("duplicate APK entry: %s", f.Name)
		}
		seen[f.Name] = true
		if !strings.HasPrefix(f.Name, "lib/") || !strings.HasSuffix(f.Name, ".so") {
			continue
		}
		parts := strings.Split(f.Name, "/")
		if len(parts) != 3 {
			return fmt.Errorf("invalid native entry: %s", f.Name)
		}
		machine, ok := machines[parts[1]]
		if !ok {
			return fmt.Errorf("unsupported native ABI: %s", parts[1])
		}
		data, err := readEntry(f, 128<<20)
		if err != nil {
			return err
		}
		if err := checkELF(data, machine); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	for abi := range machines {
		if !seen["lib/"+abi+"/libgojni.so"] {
			return fmt.Errorf("missing Go JNI library for %s", abi)
		}
	}
	return nil
}

func checkArchive(path string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	files := make(map[string]*zip.File)
	for _, f := range r.File {
		if _, exists := files[f.Name]; exists {
			return fmt.Errorf("duplicate archive entry: %s", f.Name)
		}
		files[f.Name] = f
	}
	data, err := readEntry(files["AndroidManifest.xml"], 1<<20)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	var manifest struct {
		XMLName xml.Name `xml:"manifest"`
		SDK     []struct {
			Min string `xml:"http://schemas.android.com/apk/res/android minSdkVersion,attr"`
			Max string `xml:"http://schemas.android.com/apk/res/android maxSdkVersion,attr"`
		} `xml:"uses-sdk"`
	}
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return err
	}
	if len(manifest.SDK) != 1 || manifest.SDK[0].Min != "31" || manifest.SDK[0].Max != "" {
		return errors.New("manifest must declare minSdkVersion=31 and no maxSdkVersion")
	}
	jar, err := readEntry(files["classes.jar"], 4<<20)
	if err != nil {
		return err
	}
	classes, err := zip.NewReader(bytes.NewReader(jar), int64(len(jar)))
	if err != nil {
		return err
	}
	for _, required := range []string{"com/nexusfireman/gomap/mobile/Mobile.class", "com/nexusfireman/gomap/mobile/Session.class", "go/Seq.class"} {
		found := false
		for _, f := range classes.File {
			if f.Name == required {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("missing Java class: %s", required)
		}
	}
	expected := map[string]elf.Machine{
		"jni/arm64-v8a/libgojni.so": elf.EM_AARCH64,
		"jni/x86_64/libgojni.so":    elf.EM_X86_64,
	}
	for name, machine := range expected {
		data, err := readEntry(files[name], 128<<20)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := checkELF(data, machine); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	for name := range files {
		if strings.HasPrefix(name, "jni/") && strings.HasSuffix(name, ".so") {
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("unexpected native library: %s", name)
			}
		}
	}
	return nil
}

func readEntry(f *zip.File, limit int64) ([]byte, error) {
	if f == nil {
		return nil, errors.New("missing archive entry")
	}
	if f.UncompressedSize64 > uint64(limit) {
		return nil, errors.New("archive entry exceeds size limit")
	}
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("archive entry exceeds size limit")
	}
	return data, nil
}

func checkELF(data []byte, machine elf.Machine) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if f.Type != elf.ET_DYN || f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != machine {
		return errors.New("unexpected native library type or architecture")
	}
	loads := 0
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		loads++
		if p.Align < pageSize || p.Align&(p.Align-1) != 0 || p.Vaddr%p.Align != p.Off%p.Align {
			return errors.New("native LOAD segment is not 16 KB aligned")
		}
	}
	if loads == 0 {
		return errors.New("native library has no LOAD segments")
	}
	return nil
}
