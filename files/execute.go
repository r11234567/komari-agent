package files

import (
	"bytes"
	"encoding/json"
	"fmt"

	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Execute runs one file control or stream operation and converts its JSON
// payload into the typed agent event.
func Execute(operation filev1.FileOperation, args map[string]any) *filev1.AgentFileEvent {
	event := &filev1.AgentFileEvent{Operation: operation}
	name := operationName(operation)
	if override := argString(args, "_op"); override != "" {
		name = override
	}
	if name == "" {
		event.Error = fmt.Sprintf("unsupported file operation: %s", operation.String())
		return event
	}
	payload, err := execute(name, args)
	if err != nil {
		event.Error = err.Error()
		return event
	}
	event.Path = eventPath(name, args)
	event.Success = true
	if name == "search" {
		decodeSearch(event, payload)
		return event
	}
	entries := decodeEntries(payload)
	if len(entries) == 0 && needsStatAfter(name) {
		if stat, statErr := statFile(event.Path); statErr == nil {
			entries = decodeEntries(stat)
		}
	}
	event.Entries = entries
	return event
}

func execute(operation string, args map[string]any) (json.RawMessage, error) {
	switch operation {
	case "list":
		return listFiles(argString(args, "path"))
	case "list_roots":
		return listFilesystemRoots()
	case "stat":
		return statFile(argString(args, "path"))
	case "create":
		return createFile(argString(args, "path"))
	case "mkdir":
		return mkdir(argString(args, "path"), argString(args, "mode"))
	case "delete":
		return deletePath(argString(args, "path"))
	case "move":
		return movePath(argString(args, "source"), argString(args, "destination"))
	case "copy":
		return copyPath(argString(args, "source"), argString(args, "destination"))
	case "chmod":
		return chmodPath(argString(args, "path"), argString(args, "mode"))
	case "chown":
		return chownPath(args)
	case "search":
		return searchFiles(args)
	case "download_stream":
		return sendDownloadStream(args)
	case "upload_stream":
		return receiveUploadStream(args)
	case "upload_commit":
		return commitFileUpload(args)
	case "upload_cancel":
		return cancelFileUpload(args)
	default:
		return nil, fmt.Errorf("unsupported file operation: %s", operation)
	}
}

func operationName(operation filev1.FileOperation) string {
	switch operation {
	case filev1.FileOperation_FILE_OPERATION_LIST:
		return "list"
	case filev1.FileOperation_FILE_OPERATION_LIST_ROOTS:
		return "list_roots"
	case filev1.FileOperation_FILE_OPERATION_STAT:
		return "stat"
	case filev1.FileOperation_FILE_OPERATION_CREATE:
		return "create"
	case filev1.FileOperation_FILE_OPERATION_MKDIR:
		return "mkdir"
	case filev1.FileOperation_FILE_OPERATION_DELETE:
		return "delete"
	case filev1.FileOperation_FILE_OPERATION_MOVE:
		return "move"
	case filev1.FileOperation_FILE_OPERATION_COPY:
		return "copy"
	case filev1.FileOperation_FILE_OPERATION_CHMOD:
		return "chmod"
	case filev1.FileOperation_FILE_OPERATION_CHOWN:
		return "chown"
	case filev1.FileOperation_FILE_OPERATION_SEARCH:
		return "search"
	case filev1.FileOperation_FILE_OPERATION_DOWNLOAD_STREAM:
		return "download_stream"
	case filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM:
		return "upload_stream"
	default:
		return ""
	}
}

func needsStatAfter(operation string) bool {
	switch operation {
	case "create", "mkdir", "move", "copy", "chmod", "chown":
		return true
	default:
		return false
	}
}

func eventPath(operation string, args map[string]any) string {
	switch operation {
	case "move", "copy":
		return argString(args, "destination")
	case "list_roots":
		return ""
	default:
		return argString(args, "path")
	}
}

func decodeEntries(payload json.RawMessage) []*filev1.FileEntry {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var files []fileInfo
		if err := json.Unmarshal(trimmed, &files); err != nil {
			return nil
		}
		entries := make([]*filev1.FileEntry, 0, len(files))
		for _, file := range files {
			entries = append(entries, fileEntry(file))
		}
		return entries
	case '{':
		var file fileInfo
		if err := json.Unmarshal(trimmed, &file); err != nil || file.Path == "" {
			return nil
		}
		return []*filev1.FileEntry{fileEntry(file)}
	default:
		return nil
	}
}

func fileEntry(file fileInfo) *filev1.FileEntry {
	entry := &filev1.FileEntry{
		Name:      file.Name,
		Path:      file.Path,
		Directory: file.IsDir,
		Symlink:   file.IsSymlink,
		Mode:      file.Mode,
		ModeOctal: file.ModeOctal,
		Uid:       int32(file.UID),
		Gid:       int32(file.GID),
		Owner:     file.Owner,
		Group:     file.Group,
		Target:    file.Target,
	}
	if file.Size > 0 {
		entry.Size = uint64(file.Size)
	}
	if !file.ModifiedAt.IsZero() {
		entry.ModifiedAt = timestamppb.New(file.ModifiedAt)
	}
	return entry
}

func decodeSearch(event *filev1.AgentFileEvent, payload json.RawMessage) {
	var result struct {
		Matches []searchMatch `json:"matches"`
		Limited bool          `json:"limited"`
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		event.Success = false
		event.Error = err.Error()
		return
	}
	matches := make([]*filev1.SearchMatch, 0, len(result.Matches))
	for _, match := range result.Matches {
		matches = append(matches, &filev1.SearchMatch{
			Path:      match.Path,
			Line:      uint32(max(match.Line, 0)),
			Text:      match.Text,
			Directory: match.IsDir,
		})
	}
	event.Matches = matches
	event.Limited = result.Limited
}
