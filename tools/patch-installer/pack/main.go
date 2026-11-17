// Command pack appends a payload zip and manifest to the installer stub.
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const magic = "KOTOBA-PATCH1"

type fileEntry struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	Size         int64  `json:"size"`
}

type manifest struct {
	Version       string      `json:"version"`
	GameExe       string      `json:"game_exe"`
	GameExeSHA256 string      `json:"game_exe_sha256"`
	Files         []fileEntry `json:"files"`
	Note          string      `json:"note"`
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "pack: "+format+"\n", a...)
	os.Exit(1)
}

func sha256File(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func main() {
	stub := flag.String("stub", "", "installer stub executable")
	source := flag.String("source", "", "directory with the deployed patch files")
	pristine := flag.String("pristine", "", "original game directory used for before-sha256")
	out := flag.String("out", "", "output self-extracting installer")
	version := flag.String("version", "1.0.0", "patch version shown by the installer")
	exeName := flag.String("exe-name", "ルリのかさね.exe", "game executable name")
	note := flag.String("note", "", "free-form note embedded in the manifest")
	flag.Parse()
	if *stub == "" || *source == "" || *pristine == "" || *out == "" {
		die("-stub, -source, -pristine and -out are required")
	}

	exePath := filepath.Join(*pristine, *exeName)
	exeSum, _, err := sha256File(exePath)
	if err != nil {
		die("cannot hash game exe: %v", err)
	}

	var rels []string
	for _, name := range []string{"winmm.dll", "update.arc", "fastdata.arc"} {
		if _, err := os.Stat(filepath.Join(*source, name)); err != nil {
			die("missing %s in source: %v", name, err)
		}
		rels = append(rels, name)
	}
	scenDir := filepath.Join(*source, "scenario")
	var scen []string
	err = filepath.Walk(scenDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(*source, path)
		if err != nil {
			return err
		}
		scen = append(scen, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		die("cannot list scenario: %v", err)
	}
	if len(scen) == 0 {
		die("no scripts under %s", scenDir)
	}
	sort.Strings(scen)
	rels = append(rels, scen...)

	man := manifest{Version: *version, GameExe: *exeName, GameExeSHA256: exeSum, Note: *note}
	for _, rel := range rels {
		src := filepath.Join(*source, filepath.FromSlash(rel))
		sum, size, err := sha256File(src)
		if err != nil {
			die("cannot hash %s: %v", rel, err)
		}
		entry := fileEntry{Path: rel, SHA256: sum, Size: size}
		if before, _, err := sha256File(filepath.Join(*pristine, filepath.FromSlash(rel))); err == nil {
			entry.BeforeSHA256 = before
		}
		man.Files = append(man.Files, entry)
	}

	stubInfo, err := os.Stat(*stub)
	if err != nil {
		die("cannot stat stub: %v", err)
	}

	outFile, err := os.Create(*out)
	if err != nil {
		die("cannot create %s: %v", *out, err)
	}
	defer outFile.Close()
	stubData, err := os.ReadFile(*stub)
	if err != nil {
		die("cannot read stub: %v", err)
	}
	if _, err = outFile.Write(stubData); err != nil {
		die("cannot write stub: %v", err)
	}

	manBytes, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		die("manifest marshal: %v", err)
	}

	// Zip goes to a temp file: payloads are hundreds of MB.
	tmpZip, err := os.CreateTemp(filepath.Dir(*out), ".kotoba-payload-*.zip")
	if err != nil {
		die("temp zip: %v", err)
	}
	tmpName := tmpZip.Name()
	defer os.Remove(tmpName)
	zw := zip.NewWriter(tmpZip)
	for _, e := range man.Files {
		src := filepath.Join(*source, filepath.FromSlash(e.Path))
		in, err := os.Open(src)
		if err != nil {
			die("open %s: %v", e.Path, err)
		}
		info, err := in.Stat()
		if err != nil {
			in.Close()
			die("stat %s: %v", e.Path, err)
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			in.Close()
			die("zip header %s: %v", e.Path, err)
		}
		hdr.Name = e.Path
		hdr.Method = zip.Store
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			in.Close()
			die("zip entry %s: %v", e.Path, err)
		}
		if _, err = io.Copy(w, in); err != nil {
			in.Close()
			die("zip copy %s: %v", e.Path, err)
		}
		in.Close()
		fmt.Printf("  + %s (%d bytes)\n", e.Path, e.Size)
	}
	if err = zw.Close(); err != nil {
		die("zip close: %v", err)
	}
	zipLen, err := tmpZip.Seek(0, io.SeekCurrent)
	if err != nil {
		die("zip size: %v", err)
	}
	_ = stubInfo

	if _, err = outFile.Write(manBytes); err != nil {
		die("write manifest: %v", err)
	}
	if _, err = tmpZip.Seek(0, io.SeekStart); err != nil {
		die("zip rewind: %v", err)
	}
	if _, err = io.Copy(outFile, tmpZip); err != nil {
		die("write zip: %v", err)
	}
	tmpZip.Close()
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:8], uint64(len(manBytes)))
	binary.LittleEndian.PutUint64(lens[8:16], uint64(zipLen))
	if _, err = outFile.Write(lens[:]); err != nil {
		die("write trailer: %v", err)
	}
	if _, err = outFile.Write([]byte(magic)); err != nil {
		die("write magic: %v", err)
	}
	if err = outFile.Sync(); err != nil {
		die("sync: %v", err)
	}
	finalInfo, _ := outFile.Stat()
	fmt.Printf("packed %d files, %s, %.1f MB\n", len(man.Files), *out, float64(finalInfo.Size())/1024/1024)
}
