//go:build linux || darwin || freebsd

package files

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func tempFailureRetry(fn func() error) error {
	for {
		err := fn()
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

func splitComponentsNoSymlinks(path string) (startPath string, parts []string, err error) {
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == "" {
		return ".", nil, nil
	}
	if filepath.IsAbs(cleaned) {
		startPath = "/"
		trimmed := strings.TrimPrefix(cleaned, "/")
		if trimmed != "" {
			parts = strings.Split(trimmed, "/")
		}
		return startPath, parts, nil
	}
	parts = strings.Split(cleaned, "/")
	filtered := parts[:0]
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", nil, errors.New("parent traversal is not allowed during symlink-safe open")
		}
		filtered = append(filtered, part)
	}
	return ".", filtered, nil
}

func openDirWalkNoSymlinks(path string, createDirs bool, dirMode fs.FileMode) (*os.File, error) {
	if !createDirs {
		if dir, err := openNoSymlinksFast(path, unix.O_RDONLY|unix.O_DIRECTORY, 0); dir != nil || err != nil {
			return dir, err
		}
	}
	startPath, parts, err := splitComponentsNoSymlinks(path)
	if err != nil {
		return nil, err
	}
	var curFD int
	if err := tempFailureRetry(func() error {
		var openErr error
		curFD, openErr = unix.Openat(unix.AT_FDCWD, startPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		return openErr
	}); err != nil {
		return nil, &os.PathError{Op: "open", Path: startPath, Err: err}
	}
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if createDirs {
			mkdirErr := tempFailureRetry(func() error {
				return unix.Mkdirat(curFD, part, uint32(dirMode.Perm()))
			})
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(curFD)
				return nil, &os.PathError{Op: "mkdirat", Path: part, Err: mkdirErr}
			}
		}
		var nextFD int
		openErr := tempFailureRetry(func() error {
			var e error
			nextFD, e = unix.Openat(curFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			return e
		})
		_ = unix.Close(curFD)
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) || errors.Is(openErr, unix.ENOTDIR) {
				return nil, fmt.Errorf("refusing symlink or non-directory component %q: %w", part, openErr)
			}
			return nil, &os.PathError{Op: "openat", Path: part, Err: openErr}
		}
		curFD = nextFD
	}
	return os.NewFile(uintptr(curFD), path), nil
}

func openParentNoSymlinks(path string, createDirs bool, dirMode fs.FileMode) (*os.File, string, error) {
	cleaned := filepath.Clean(path)
	base := filepath.Base(cleaned)
	if base == "" || base == "." || base == "/" || base == ".." {
		return nil, "", errors.New("file path must include an entry name")
	}
	parentPath := filepath.Dir(cleaned)
	parent, err := openDirWalkNoSymlinks(parentPath, createDirs, dirMode)
	if err != nil {
		return nil, "", err
	}
	return parent, base, nil
}

func openInDir(dir *os.File, name string, flags int, mode uint32) (*os.File, error) {
	var fd int
	openFlags := flags | unix.O_NOFOLLOW | unix.O_CLOEXEC
	err := tempFailureRetry(func() error {
		var e error
		fd, e = unix.Openat(int(dir.Fd()), name, openFlags, mode)
		return e
	})
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refusing to follow symlink %q: %w", name, err)
		}
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(dir.Name(), name)), nil
}

func openNoSymlinks(path string, flags int, mode uint32) (*os.File, error) {
	if file, err := openNoSymlinksFast(path, flags, mode); file != nil || err != nil {
		return file, err
	}
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return openInDir(parent, base, flags, mode)
}

func openRegularNoSymlinks(path string, flags int, mode uint32) (*os.File, os.FileInfo, error) {
	file, err := openNoSymlinks(path, flags|unix.O_NONBLOCK|unix.O_NOCTTY, mode)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("cannot operate on a non-regular file")
	}
	return file, info, nil
}

func statNoFollowInDir(dir *os.File, name string) (*unix.Stat_t, error) {
	var st unix.Stat_t
	err := tempFailureRetry(func() error {
		return unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	})
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		return nil, &os.PathError{Op: "fstatat", Path: name, Err: err}
	}
	return &st, nil
}

func createTempInDir(dir *os.File, prefix string) (*os.File, string, error) {
	for i := 0; i < 64; i++ {
		name := prefix + rand.Text()
		file, err := openInDir(dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return nil, "", err
	}
	return nil, "", errors.New("exhausted temporary filenames")
}

func unlinkatSafe(dir *os.File, name string, recursive bool) error {
	st, err := statNoFollowInDir(dir, name)
	if err != nil {
		return err
	}
	if st == nil {
		return &os.PathError{Op: "unlinkat", Path: name, Err: os.ErrNotExist}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return tempFailureRetry(func() error {
			return unix.Unlinkat(int(dir.Fd()), name, 0)
		})
	}
	if !recursive {
		return tempFailureRetry(func() error {
			return unix.Unlinkat(int(dir.Fd()), name, unix.AT_REMOVEDIR)
		})
	}
	subDir, err := openInDir(dir, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	entries, readErr := subDir.Readdirnames(-1)
	if readErr != nil {
		_ = subDir.Close()
		return readErr
	}
	for _, entry := range entries {
		if entry == "." || entry == ".." {
			continue
		}
		if err := unlinkatSafe(subDir, entry, true); err != nil {
			_ = subDir.Close()
			return err
		}
	}
	_ = subDir.Close()
	return tempFailureRetry(func() error {
		return unix.Unlinkat(int(dir.Fd()), name, unix.AT_REMOVEDIR)
	})
}

func deletePathSafe(path string, recursive bool) error {
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	return unlinkatSafe(parent, base, recursive)
}

func mkdirSafe(path string, mode fs.FileMode) error {
	dir, err := openDirWalkNoSymlinks(path, true, mode)
	if err != nil {
		return err
	}
	return dir.Close()
}

func chmodSafe(path string, mode fs.FileMode) error {
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	st, err := statNoFollowInDir(parent, base)
	if err != nil {
		return err
	}
	if st == nil {
		return &os.PathError{Op: "chmod", Path: path, Err: os.ErrNotExist}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("refusing chmod on symlink %q", path)
	}
	file, openErr := openInDir(parent, base, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if openErr == nil {
		defer file.Close()
		return tempFailureRetry(func() error {
			return unix.Fchmod(int(file.Fd()), syscallMode(mode))
		})
	}
	// Older kernels without fchmodat2 fail closed when a no-follow chmod is required.
	return tempFailureRetry(func() error {
		return unix.Fchmodat(int(parent.Fd()), base, syscallMode(mode), unix.AT_SYMLINK_NOFOLLOW)
	})
}

func chownSafe(path string, uid, gid int) error {
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if err != nil {
		return err
	}
	defer parent.Close()
	return tempFailureRetry(func() error {
		return unix.Fchownat(int(parent.Fd()), base, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
	})
}

func syscallMode(i fs.FileMode) uint32 {
	o := uint32(i.Perm())
	if i&fs.ModeSetuid != 0 {
		o |= unix.S_ISUID
	}
	if i&fs.ModeSetgid != 0 {
		o |= unix.S_ISGID
	}
	if i&fs.ModeSticky != 0 {
		o |= unix.S_ISVTX
	}
	return o
}

func writeAtomicFileSafe(path string, data []byte, perm fs.FileMode, identity string) error {
	parent, err := openUploadStage(filepath.Dir(path), false)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := checkStagePartIdentity(parent, identity); err != nil {
		return err
	}
	base := filepath.Base(path)
	tmp, tmpName, err := createTempInDir(parent, "."+base+".tmp-")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = unix.Unlinkat(int(parent.Fd()), tmpName, 0)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tempFailureRetry(func() error { return unix.Fchmod(int(tmp.Fd()), syscallMode(perm)) }); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameInDir(parent, tmpName, parent, base, true); err != nil {
		return err
	}
	cleanup = false
	return tempFailureRetry(func() error { return unix.Fsync(int(parent.Fd())) })
}

func readRegularFileSafe(path string, maxBytes int64) ([]byte, error) {
	parent, err := openUploadStage(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	file, err := openInDir(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := ensurePrivatePart(file); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum %d bytes", path, maxBytes)
	}
	return data, err
}

func createEmptyRegularFileSafe(path string, hasMode bool, requestedMode fs.FileMode) error {
	parent, base, err := openParentNoSymlinks(path, true, 0o755)
	if err != nil {
		return err
	}
	defer parent.Close()
	st, err := statNoFollowInDir(parent, base)
	if err != nil {
		return err
	}
	modeBits := uint32(0o644)
	hasOwner := false
	var uid, gid int
	if st != nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("cannot replace a non-regular file; choose its regular-file target explicitly")
		}
		modeBits = uint32(st.Mode) & 0o7777
		uid, gid = int(st.Uid), int(st.Gid)
		hasOwner = true
	}
	tmp, tmpName, err := createTempInDir(parent, ".komari-empty-")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = unix.Unlinkat(int(parent.Fd()), tmpName, 0)
		}
	}()
	if hasOwner {
		if err := tempFailureRetry(func() error { return unix.Fchown(int(tmp.Fd()), uid, gid) }); err != nil {
			return fmt.Errorf("cannot preserve file ownership: %w", err)
		}
	}
	if hasMode {
		modeBits = syscallMode(requestedMode)
	}
	if err := tempFailureRetry(func() error { return unix.Fchmod(int(tmp.Fd()), modeBits) }); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameInDir(parent, tmpName, parent, base, true); err != nil {
		return err
	}
	cleanup = false
	return tempFailureRetry(func() error { return unix.Fsync(int(parent.Fd())) })
}

// A directory writer can rename the stage's entry, but only the worker can
// alter files inside the private directory reached through this descriptor.
func openUploadStage(path string, create bool) (*os.File, error) {
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if create {
		if err := unix.Mkdirat(int(parent.Fd()), base, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	}
	stage, err := openPrivateDirIn(parent, base)
	if err != nil {
		return nil, err
	}
	if create {
		if err := tempFailureRetry(func() error { return unix.Fsync(int(parent.Fd())) }); err != nil {
			_ = stage.Close()
			return nil, err
		}
	}
	return stage, nil
}

func openPrivateDirIn(parent *os.File, name string) (*os.File, error) {
	stage, err := openInDir(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(stage.Fd()), &stat); err != nil {
		_ = stage.Close()
		return nil, err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 {
		_ = stage.Close()
		return nil, errors.New("staging directory must be a worker-owned private directory")
	}
	return stage, nil
}

func ensurePrivatePart(file *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&0o077 != 0 || stat.Nlink != 1 {
		return errors.New("upload staging file must be private, regular and worker-owned")
	}
	return nil
}

func uploadPartIdentity(file *os.File) (string, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x", stat.Dev, stat.Ino), nil
}

func checkUploadPartIdentity(file *os.File, expected string) error {
	identity, err := uploadPartIdentity(file)
	if err != nil {
		return err
	}
	if identity != expected {
		return errors.New("upload part identity changed")
	}
	return nil
}

func checkStagePartIdentity(stage *os.File, expected string) error {
	file, err := openInDir(stage, "part", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return checkUploadPartIdentity(file, expected)
}

func openUploadPartSafe(partPath string, create bool) (*os.File, error) {
	stage, err := openUploadStage(filepath.Dir(partPath), create)
	if err != nil {
		return nil, err
	}
	defer stage.Close()
	name := filepath.Base(partPath)
	flags := unix.O_RDWR | unix.O_NONBLOCK
	if create {
		part, err := openInDir(stage, name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		if err == nil || !errors.Is(err, os.ErrExist) {
			return part, err
		}
	}
	part, err := openInDir(stage, name, flags, 0)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivatePart(part); err != nil {
		_ = part.Close()
		return nil, err
	}
	return part, nil
}

func removeUploadStage(path, identity string) error {
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	stage, err := openPrivateDirIn(parent, base)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer stage.Close()
	if err := checkStagePartIdentity(stage, identity); err != nil {
		return err
	}
	for _, name := range []string{"part", "manifest.json"} {
		if err := unix.Unlinkat(int(stage.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	if err := unix.Unlinkat(int(parent.Fd()), base, unix.AT_REMOVEDIR); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func commitUploadPartSafe(partPath, targetPath string, totalSize int64, identity string) error {
	parent, targetBase, err := openParentNoSymlinks(targetPath, true, 0o755)
	if err != nil {
		return err
	}
	defer parent.Close()
	partDir := filepath.Dir(partPath)
	if !samePath(filepath.Dir(partDir), filepath.Dir(targetPath)) {
		return errors.New("upload part must be staged beside its destination")
	}
	stageBase := filepath.Base(partDir)
	partParent, err := openPrivateDirIn(parent, stageBase)
	if err != nil {
		return err
	}
	defer partParent.Close()

	partBase := filepath.Base(partPath)
	partFile, err := openInDir(partParent, partBase, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer partFile.Close()
	if err := ensurePrivatePart(partFile); err != nil {
		return err
	}
	if err := checkUploadPartIdentity(partFile, identity); err != nil {
		return err
	}
	partInfo, err := partFile.Stat()
	if err != nil {
		return err
	}
	if partInfo.Size() < totalSize {
		return fmt.Errorf("upload part file is %d bytes, want %d", partInfo.Size(), totalSize)
	}
	st, err := statNoFollowInDir(parent, targetBase)
	if err != nil {
		return err
	}
	if st != nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("cannot replace a non-regular file; choose its regular-file target explicitly")
	}
	// Keep the resumable part private and worker-owned until publication succeeds.
	publication, publicationName, err := createTempInDir(partParent, ".publish-")
	if err != nil {
		return err
	}
	defer func() {
		_ = publication.Close()
		_ = unix.Unlinkat(int(partParent.Fd()), publicationName, 0)
	}()
	if _, err := io.CopyN(publication, partFile, totalSize); err != nil {
		return err
	}
	modeBits := uint32(0o644)
	if st != nil {
		modeBits = uint32(st.Mode) & 0o777
		if err := tempFailureRetry(func() error { return unix.Fchown(int(publication.Fd()), int(st.Uid), int(st.Gid)) }); err != nil {
			return fmt.Errorf("cannot preserve file ownership: %w", err)
		}
	}
	if err := tempFailureRetry(func() error { return unix.Fchmod(int(publication.Fd()), modeBits) }); err != nil {
		return err
	}
	if err := publication.Sync(); err != nil {
		return err
	}
	if err := renameInDir(partParent, publicationName, parent, targetBase, true); err != nil {
		return err
	}
	if err := tempFailureRetry(func() error { return unix.Fsync(int(parent.Fd())) }); err != nil {
		return err
	}
	_ = unix.Unlinkat(int(partParent.Fd()), partBase, 0)
	_ = unix.Unlinkat(int(partParent.Fd()), "manifest.json", 0)
	_ = unix.Unlinkat(int(parent.Fd()), stageBase, unix.AT_REMOVEDIR)
	return nil
}

func moveSameDeviceSafe(source, destination string, overwrite bool) error {
	srcParent, srcBase, err := openParentNoSymlinks(source, false, 0)
	if err != nil {
		return err
	}
	defer srcParent.Close()
	dstParent, dstBase, err := openParentNoSymlinks(destination, true, 0o755)
	if err != nil {
		return err
	}
	defer dstParent.Close()
	return renameInDir(srcParent, srcBase, dstParent, dstBase, overwrite)
}
