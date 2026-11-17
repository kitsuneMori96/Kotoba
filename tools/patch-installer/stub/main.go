// Command stub is the self-extracting installer for the local patch build.
// The payload (manifest + zip + trailer) is appended to this executable by pack.
package main

import (
	"archive/zip"
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	magic       = "RURI-PATCH1"
	trailerSize = 8 + 8 + len(magic)
)

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

type installState struct {
	Version       string      `json:"version"`
	Time          string      `json:"time"`
	Files         []fileEntry `json:"files"`
	Created       []string    `json:"created"`
	GameExeSHA256 string      `json:"game_exe_sha256"`
}

const (
	backupDirName = ".ruri-backup"
	// Earlier installers used this name; adopt it in place when found.
	legacyBackupDirName = ".kotoba-backup"
)

// resolveBackupDir returns the backup directory for target, preferring the
// current name and reusing a legacy one in place (no rename, so --check and a
// cancelled install never touch the target).
func resolveBackupDir(target string) string {
	current := filepath.Join(target, backupDirName)
	if _, err := os.Stat(current); err == nil {
		return current
	}
	legacy := filepath.Join(target, legacyBackupDirName)
	if _, err := os.Stat(legacy); err == nil {
		return legacy
	}
	return current
}

func matchesOld(state installState, path, sum string) bool {
	for _, f := range state.Files {
		if f.Path == path && strings.EqualFold(f.SHA256, sum) {
			return true
		}
	}
	return false
}

func setConsoleUTF8() {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	proc := k32.NewProc("SetConsoleOutputCP")
	proc.Call(65001)
}

func fail(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "错误: "+format+"\n", a...)
	waitExit(1)
}

func waitExit(code int) {
	fmt.Print("按回车键退出...")
	bufio.NewReader(os.Stdin).ReadString('\n')
	os.Exit(code)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// safeJoin refuses anything that would resolve outside base.
func safeJoin(base, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", fmt.Errorf("非法路径: %q", rel)
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." ||
		strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("非法路径: %q", rel)
	}
	full := filepath.Join(base, clean)
	if relPath, err := filepath.Rel(base, full); err != nil || relPath == ".." ||
		strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("路径越界: %q", rel)
	}
	return full, nil
}

// readPayload parses [stub][manifest][zip][u64 manLen][u64 zipLen][magic].
func readPayload(self string) (*zip.Reader, *manifest, error) {
	info, err := os.Stat(self)
	if err != nil {
		return nil, nil, err
	}
	if info.Size() < int64(trailerSize) {
		return nil, nil, errors.New("文件过短，不是补丁安装器")
	}
	f, err := os.Open(self)
	if err != nil {
		return nil, nil, err
	}
	tail := make([]byte, trailerSize)
	if _, err = f.ReadAt(tail, info.Size()-int64(trailerSize)); err != nil {
		f.Close()
		return nil, nil, err
	}
	if string(tail[16:]) != magic {
		f.Close()
		return nil, nil, errors.New("未找到补丁载荷标记")
	}
	manLen := binary.LittleEndian.Uint64(tail[0:8])
	zipLen := binary.LittleEndian.Uint64(tail[8:16])
	payloadEnd := info.Size() - int64(trailerSize)
	if int64(manLen) > payloadEnd || int64(manLen+zipLen) > payloadEnd {
		f.Close()
		return nil, nil, errors.New("补丁载荷长度异常")
	}
	manStart := payloadEnd - int64(manLen+zipLen)
	zipStart := payloadEnd - int64(zipLen)
	manBytes := make([]byte, manLen)
	if _, err = f.ReadAt(manBytes, manStart); err != nil {
		f.Close()
		return nil, nil, err
	}
	var man manifest
	if err = json.Unmarshal(manBytes, &man); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("清单解析失败: %w", err)
	}
	zr, err := zip.NewReader(io.NewSectionReader(f, zipStart, int64(zipLen)), int64(zipLen))
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("载荷解析失败: %w", err)
	}
	return zr, &man, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmp := dst + ".ruri-tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err = out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err = out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func writeFile(dst string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	tmp := dst + ".ruri-tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, r); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err = out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err = out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func systemWinMM() string {
	windir := os.Getenv("SystemRoot")
	if windir == "" {
		windir = `C:\Windows`
	}
	for _, c := range []string{
		filepath.Join(windir, "SysWOW64", "winmm.dll"),
		filepath.Join(windir, "System32", "winmm.dll"),
	} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func verifyHash(path, want string) error {
	if want == "" {
		return nil
	}
	got, err := sha256File(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("摘要不符 got=%s want=%s", got, want)
	}
	return nil
}

func main() {
	setConsoleUTF8()
	dryRun := flag.Bool("check", false, "只检查，不写入")
	rollback := flag.Bool("rollback", false, "撤销已安装的补丁")
	yes := flag.Bool("yes", false, "跳过确认")
	dirFlag := flag.String("dir", "", "游戏目录（默认安装器所在目录）")
	flag.Parse()

	self, err := os.Executable()
	if err != nil {
		fail("无法定位安装器自身: %v", err)
	}
	target := *dirFlag
	if target == "" {
		target = filepath.Dir(self)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		fail("目录无效: %v", err)
	}

	zr, man, err := readPayload(self)
	if err != nil {
		fail("%v", err)
	}

	if *rollback {
		doRollback(target)
		return
	}

	fmt.Printf("琉璃交错 ～妹物语～ 汉化补丁 %s\n", man.Version)
	fmt.Printf("目标目录: %s\n\n", target)

	exePath := filepath.Join(target, man.GameExe)
	if _, err := os.Stat(exePath); err != nil {
		fail("未找到 %s，请把补丁放到游戏根目录（与游戏 exe 同级）", man.GameExe)
	}
	sum, err := sha256File(exePath)
	if err != nil {
		fail("读取游戏 exe 失败: %v", err)
	}
	if !strings.EqualFold(sum, man.GameExeSHA256) {
		fail("游戏版本不匹配。\n期望 exe 摘要: %s\n实际 exe 摘要: %s\n本补丁只适用于该版本，未做任何修改。", man.GameExeSHA256, sum)
	}

	backupDir := resolveBackupDir(target)
	installed := false
	var oldState installState
	if _, err := os.Stat(backupDir); err == nil {
		if _, err2 := os.Stat(filepath.Join(backupDir, "install.json")); err2 == nil {
			fmt.Println("检测到本补丁的备份目录，将视为重新安装（不重复备份）。")
			installed = true
			if raw, err := os.ReadFile(filepath.Join(backupDir, "install.json")); err == nil {
				_ = json.Unmarshal(raw, &oldState)
			}
		} else {
			fail("目录 %s 已存在但不是本补丁的备份，请先手动确认后移除。", backupDir)
		}
	}

	type plan struct {
		entry   fileEntry
		zipFile *zip.File
		dst     string
	}
	var plans []plan
	var total int64
	for _, e := range man.Files {
		dst, err := safeJoin(target, e.Path)
		if err != nil {
			fail("%v", err)
		}
		var zf *zip.File
		for _, z := range zr.File {
			if z.Name == e.Path {
				zf = z
				break
			}
		}
		if zf == nil {
			fail("载荷缺少文件: %s", e.Path)
		}
		cur, statErr := sha256File(dst)
		switch {
		case statErr == nil:
			if strings.EqualFold(cur, e.SHA256) {
				// already this version
			} else if e.BeforeSHA256 != "" && strings.EqualFold(cur, e.BeforeSHA256) {
				// pristine, will be replaced
			} else if installed && matchesOld(oldState, e.Path, cur) {
				// previous version of this patch, will be upgraded
			} else if installed {
				fail("文件 %s 与预期不符（既非原版也非本补丁），已中止。", e.Path)
			} else {
				fail("文件 %s 已被修改（摘要 %s）。为安全起见不做覆盖。", e.Path, cur)
			}
		case os.IsNotExist(statErr):
			if e.BeforeSHA256 != "" {
				fail("缺少原版文件 %s，游戏目录不完整。", e.Path)
			}
		default:
			fail("无法读取 %s: %v", e.Path, statErr)
		}
		total += e.Size
		plans = append(plans, plan{e, zf, dst})
	}
	systemDLL := systemWinMM()
	origDLL := filepath.Join(target, "winmm_orig.dll")
	if _, err := os.Stat(origDLL); err != nil {
		if systemDLL == "" {
			fail("未找到系统 winmm.dll，无法生成 winmm_orig.dll。")
		}
		fmt.Printf("将从 %s 生成 winmm_orig.dll\n", systemDLL)
	}

	fmt.Printf("将写入 %d 个文件，共 %.1f MB。\n", len(plans), float64(total)/1024/1024)
	if *dryRun {
		for _, p := range plans {
			fmt.Printf("  %s (%d 字节)\n", p.entry.Path, p.entry.Size)
		}
		fmt.Println("检查通过，未做任何修改（--check）。")
		waitExit(0)
	}
	if !*yes {
		fmt.Print("确认安装？[y/N] ")
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		ans = strings.ToLower(strings.TrimSpace(ans))
		if ans != "y" && ans != "yes" {
			fmt.Println("已取消。")
			return
		}
	}

	state := installState{
		Version:       man.Version,
		Time:          time.Now().Format(time.RFC3339),
		Files:         man.Files,
		GameExeSHA256: man.GameExeSHA256,
	}

	if installed {
		for _, c := range oldState.Created {
			state.Created = append(state.Created, c)
		}
	} else {
		if err := os.Mkdir(backupDir, 0755); err != nil {
			fail("创建备份目录失败: %v", err)
		}
		for _, p := range plans {
			if _, err := os.Stat(p.dst); err == nil {
				bak, err := safeJoin(backupDir, p.entry.Path)
				if err != nil {
					fail("%v", err)
				}
				if err := copyFile(p.dst, bak); err != nil {
					fail("备份 %s 失败: %v", p.entry.Path, err)
				}
				if err := verifyHash(bak, p.entry.BeforeSHA256); err != nil && p.entry.BeforeSHA256 != "" {
					fail("备份 %s 校验失败: %v", p.entry.Path, err)
				}
			} else {
				state.Created = append(state.Created, p.entry.Path)
			}
		}
	}

	written := []string{}
	for i, p := range plans {
		rc, err := p.zipFile.Open()
		if err != nil {
			restore(target, backupDir, state, written)
			fail("读取载荷 %s 失败: %v（已尝试回退）", p.entry.Path, err)
		}
		err = writeFile(p.dst, rc)
		rc.Close()
		if err != nil {
			restore(target, backupDir, state, written)
			fail("写入 %s 失败: %v（已尝试回退，请关闭游戏后重试）", p.entry.Path, err)
		}
		written = append(written, p.entry.Path)
		if err := verifyHash(p.dst, p.entry.SHA256); err != nil {
			restore(target, backupDir, state, written)
			fail("%s 写入后校验失败（已尝试回退）", p.entry.Path)
		}
		fmt.Printf("  [%d/%d] %s\n", i+1, len(plans), p.entry.Path)
	}

	if installed {
		newPaths := map[string]bool{}
		for _, e := range man.Files {
			newPaths[e.Path] = true
		}
		oldCreated := map[string]bool{}
		for _, c := range oldState.Created {
			oldCreated[c] = true
		}
		removed := 0
		for _, f := range oldState.Files {
			if newPaths[f.Path] || !oldCreated[f.Path] {
				continue
			}
			dst, err := safeJoin(target, f.Path)
			if err != nil {
				continue
			}
			got, err := sha256File(dst)
			if err != nil || !strings.EqualFold(got, f.SHA256) {
				continue
			}
			if os.Remove(dst) == nil {
				fmt.Printf("  移除旧版多余文件 %s\n", f.Path)
				removed++
			}
		}
		if removed > 0 {
			var kept []string
			for _, c := range state.Created {
				if newPaths[c] || c == "winmm_orig.dll" {
					kept = append(kept, c)
				}
			}
			state.Created = kept
			os.Remove(filepath.Join(target, "scenario"))
		}
	}

	if _, err := os.Stat(origDLL); err != nil {
		if err := copyFile(systemDLL, origDLL); err != nil {
			fmt.Printf("警告: 生成 winmm_orig.dll 失败: %v\n请手动把系统 winmm.dll 复制为 winmm_orig.dll。\n", err)
		} else {
			state.Created = append(state.Created, "winmm_orig.dll")
		}
	}

	sort.Strings(state.Created)
	data, _ := json.MarshalIndent(state, "", "  ")
	if err := writeFile(filepath.Join(backupDir, "install.json"), strings.NewReader(string(data))); err != nil {
		fail("写入安装状态失败: %v", err)
	}
	fmt.Printf("\n安装完成。备份与原文件摘要记录在 %s。\n", filepath.Base(backupDir))
	fmt.Println("如需撤销：运行本程序并加参数 --rollback。")
	waitExit(0)
}

func restore(target, backupDir string, state installState, written []string) {
	created := map[string]bool{}
	for _, c := range state.Created {
		created[c] = true
	}
	for _, rel := range written {
		dst, err := safeJoin(target, rel)
		if err != nil {
			continue
		}
		if created[rel] {
			os.Remove(dst)
			continue
		}
		bak, err := safeJoin(backupDir, rel)
		if err != nil {
			continue
		}
		if _, err := os.Stat(bak); err == nil {
			copyFile(bak, dst)
		}
	}
}

func doRollback(target string) {
	backupDir := resolveBackupDir(target)
	raw, err := os.ReadFile(filepath.Join(backupDir, "install.json"))
	if err != nil {
		fail("未找到安装状态，无法撤销: %v", err)
	}
	var state installState
	if err := json.Unmarshal(raw, &state); err != nil {
		fail("安装状态损坏: %v", err)
	}
	fmt.Printf("将撤销补丁 %s（安装于 %s）。\n", state.Version, state.Time)
	for _, f := range state.Files {
		cur, err := safeJoin(target, f.Path)
		if err != nil {
			fail("%v", err)
		}
		got, err := sha256File(cur)
		if err != nil {
			continue
		}
		if !strings.EqualFold(got, f.SHA256) {
			fail("文件 %s 已被外部修改，拒绝撤销以免覆盖。", f.Path)
		}
	}
	created := map[string]bool{}
	for _, c := range state.Created {
		created[c] = true
	}
	for _, f := range state.Files {
		cur, err := safeJoin(target, f.Path)
		if err != nil {
			fail("%v", err)
		}
		if created[f.Path] {
			os.Remove(cur)
			fmt.Printf("  删除 %s\n", f.Path)
			continue
		}
		bak, err := safeJoin(backupDir, f.Path)
		if err != nil {
			fail("%v", err)
		}
		if err := copyFile(bak, cur); err != nil {
			fail("恢复 %s 失败: %v", f.Path, err)
		}
		if err := verifyHash(cur, f.BeforeSHA256); err != nil {
			fail("恢复 %s 后校验失败: %v", f.Path, err)
		}
		fmt.Printf("  恢复 %s\n", f.Path)
	}
	if created["winmm_orig.dll"] {
		os.Remove(filepath.Join(target, "winmm_orig.dll"))
		fmt.Println("  删除 winmm_orig.dll")
	}
	os.Remove(filepath.Join(backupDir, "install.json"))
	entries, _ := os.ReadDir(backupDir)
	for _, e := range entries {
		if !e.IsDir() {
			os.Remove(filepath.Join(backupDir, e.Name()))
		}
	}
	os.RemoveAll(backupDir)
	os.Remove(filepath.Join(target, "scenario"))
	fmt.Println("撤销完成。")
	waitExit(0)
}
