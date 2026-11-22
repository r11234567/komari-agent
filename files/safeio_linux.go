//go:build linux

package files

import (
	"errors"
	"fmt"
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

func openat2NoSymlinks(path string, flags int, mode uint32) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	if flags&(unix.O_CREAT|unix.O_TMPFILE) != 0 {
		how.Mode = uint64(mode)
	}
	var fd int
	err := tempFailureRetry(func() error {
		var openErr error
		fd, openErr = unix.Openat2(unix.AT_FDCWD, path, how)
		return openErr
	})
	return fd, err
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
		fd, err := openat2NoSymlinks(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err == nil {
			return os.NewFile(uintptr(fd), path), nil
		}
		if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
			return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
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
	if base == "" || base == "." || base == "/" {
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
	var openMode uint32
	if openFlags&(unix.O_CREAT|unix.O_TMPFILE) != 0 {
		openMode = mode
	}
	err := tempFailureRetry(func() error {
		var e error
		fd, e = unix.Openat(int(dir.Fd()), name, openFlags, openMode)
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
	fd, err := openat2NoSymlinks(path, flags, mode)
	if err == nil {
		return os.NewFile(uintptr(fd), path), nil
	}
	if !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EPERM) {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("refusing to traverse symlink at %q: %w", path, err)
		}
		return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
	}
	parent, base, err := openParentNoSymlinks(path, false, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return openInDir(parent, base, flags, mode)
}

func openRegularNoSymlinks(path string, flags int, mode uint32) (*os.File, os.FileInfo, error) {
	file, err := openNoSymlinks(path, flags, mode)
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

func renameInDir(srcDir *os.File, srcName string, dstDir *os.File, dstName string, overwrite bool) error {
	var flags uint
	if !overwrite {
		flags = unix.RENAME_NOREPLACE
	}
	return tempFailureRetry(func() error {
		return unix.Renameat2(int(srcDir.Fd()), srcName, int(dstDir.Fd()), dstName, flags)
	})
}

func createTempInDir(dir *os.File, prefix string) (*os.File, string, error) {
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("%s%d-%d", prefix, os.Getpid(), i)
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
	file, openErr := openInDir(parent, base, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if openErr == nil {
		defer file.Close()
		return tempFailureRetry(func() error {
			return unix.Fchmod(int(file.Fd()), syscallMode(mode))
		})
	}
	return tempFailureRetry(func() error {
		return unix.Fchmodat(int(parent.Fd()), base, syscallMode(mode), 0)
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

func writeAtomicFileSafe(path string, data []byte, perm fs.FileMode) error {
	parent, base, err := openParentNoSymlinks(path, true, 0o755)
	if err != nil {
		return err
	}
	defer parent.Close()
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
	file, info, err := openRegularNoSymlinks(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum %d bytes", path, maxBytes)
	}
	buf := make([]byte, info.Size())
	n := 0
	for n < len(buf) {
		readN, readErr := file.Read(buf[n:])
		n += readN
		if readErr != nil {
			if readN > 0 {
				continue
			}
			break
		}
	}
	return buf[:n], nil
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
		modeBits = st.Mode & 0o7777
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

func openUploadPartSafe(partPath string, truncate bool) (*os.File, error) {
	parent, base, err := openParentNoSymlinks(partPath, false, 0)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	flags := unix.O_WRONLY | unix.O_CREAT
	if truncate {
		flags |= unix.O_TRUNC
	}
	return openInDir(parent, base, flags, 0o600)
}

func commitUploadPartSafe(partPath, targetPath string, totalSize int64) error {
	parent, targetBase, err := openParentNoSymlinks(targetPath, true, 0o755)
	if err != nil {
		return err
	}
	defer parent.Close()
	partParent, partBase, err := openParentNoSymlinks(partPath, false, 0)
	if err != nil {
		return err
	}
	defer partParent.Close()

	partFile, err := openInDir(partParent, partBase, unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer partFile.Close()
	partInfo, err := partFile.Stat()
	if err != nil {
		return err
	}
	if !partInfo.Mode().IsRegular() {
		return errors.New("upload part file must be a regular file")
	}
	if partInfo.Size() < totalSize {
		return fmt.Errorf("upload part file is %d bytes, want %d", partInfo.Size(), totalSize)
	}
	if partInfo.Size() > totalSize {
		if err := partFile.Truncate(totalSize); err != nil {
			return err
		}
	}
	st, err := statNoFollowInDir(parent, targetBase)
	if err != nil {
		return err
	}
	modeBits := uint32(0o644)
	if st != nil {
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("cannot replace a non-regular file; choose its regular-file target explicitly")
		}
		modeBits = st.Mode & 0o7777
		if err := tempFailureRetry(func() error { return unix.Fchown(int(partFile.Fd()), int(st.Uid), int(st.Gid)) }); err != nil {
			return fmt.Errorf("cannot preserve file ownership: %w", err)
		}
	}
	if err := tempFailureRetry(func() error { return unix.Fchmod(int(partFile.Fd()), modeBits) }); err != nil {
		return err
	}
	if err := partFile.Sync(); err != nil {
		return err
	}
	if err := partFile.Close(); err != nil {
		return err
	}
	if err := renameInDir(partParent, partBase, parent, targetBase, true); err != nil {
		return err
	}
	return tempFailureRetry(func() error { return unix.Fsync(int(parent.Fd())) })
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
