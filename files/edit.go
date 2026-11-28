package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"strings"
)

const maxEditableSize = 2 << 20

var errFileEditConflict = errors.New("file changed since it was opened")

func replaceEditedFile(args map[string]any) error {
	path := argString(args, "path")
	if strings.TrimSpace(path) == "" {
		return errors.New("edit requires a file path")
	}
	encoded := argString(args, "content")
	if len(encoded) > base64.StdEncoding.EncodedLen(maxEditableSize) {
		return errors.New("edited file exceeds size limit")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	expected, digestErr := base64.StdEncoding.DecodeString(argString(args, "expected_digest"))
	if err != nil || digestErr != nil || len(expected) != sha256.Size || len(data) > maxEditableSize {
		return errors.New("invalid file edit content or version")
	}
	return replaceEditedFileSafe(resolveFilePath(path), data, expected)
}

func verifyEditedFile(file *os.File, expected []byte) (os.FileInfo, error) {
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxEditableSize {
		return nil, errFileEditConflict
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(file, maxEditableSize+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if count != before.Size() || !unchangedEditTarget(before, after) || !bytes.Equal(digest.Sum(nil), expected) {
		return nil, errFileEditConflict
	}
	return after, nil
}

func unchangedEditTarget(before, after os.FileInfo) bool {
	return after.Mode().IsRegular() && os.SameFile(before, after) && before.Size() == after.Size() &&
		before.Mode() == after.Mode() && before.ModTime().Equal(after.ModTime())
}
