package files

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ExecuteAssignment executes one strongly-typed FileAssignment without reading
// deprecated untyped Arguments or _op overrides.
func ExecuteAssignment(assignment *filev1.FileAssignment) *filev1.AgentFileEvent {
	if assignment == nil {
		return &filev1.AgentFileEvent{Error: "file assignment is required"}
	}
	args, err := assignmentArgs(assignment)
	if err != nil {
		return &filev1.AgentFileEvent{
			RequestId: assignment.GetRequestId(),
			Operation: assignment.GetOperation(),
			Error:     err.Error(),
		}
	}
	event := ExecuteWithScope(assignment.GetWorkspaceId(), assignment.GetOperation(), args)
	event.RequestId = assignment.GetRequestId()
	return event
}

// Execute runs one file control or stream operation and converts its JSON
// payload into the typed agent event.
func Execute(operation filev1.FileOperation, args map[string]any) *filev1.AgentFileEvent {
	return ExecuteWithScope("", operation, args)
}

// ExecuteWithScope runs one file operation bound to a workspace scope.
func ExecuteWithScope(scope string, operation filev1.FileOperation, args map[string]any) *filev1.AgentFileEvent {
	event := &filev1.AgentFileEvent{Operation: operation}
	name := operationName(operation)
	if name == "" {
		event.Error = fmt.Sprintf("unsupported file operation: %s", operation.String())
		return event
	}
	payload, err := executeScoped(scope, name, args)
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

func assignmentArgs(assignment *filev1.FileAssignment) (map[string]any, error) {
	if assignment == nil {
		return nil, errors.New("file assignment is required")
	}
	op := assignment.GetOperation()
	switch p := assignment.GetPayload().(type) {
	case *filev1.FileAssignment_List:
		if op != filev1.FileOperation_FILE_OPERATION_LIST || p.List == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"path": p.List.GetPath()}, nil
	case *filev1.FileAssignment_ListRoots:
		if op != filev1.FileOperation_FILE_OPERATION_LIST_ROOTS || p.ListRoots == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{}, nil
	case *filev1.FileAssignment_Stat:
		if op != filev1.FileOperation_FILE_OPERATION_STAT || p.Stat == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"path": p.Stat.GetPath()}, nil
	case *filev1.FileAssignment_Create:
		if op != filev1.FileOperation_FILE_OPERATION_CREATE || p.Create == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"path": p.Create.GetPath(), "mode": p.Create.GetMode()}, nil
	case *filev1.FileAssignment_Mkdir:
		if op != filev1.FileOperation_FILE_OPERATION_MKDIR || p.Mkdir == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"path": p.Mkdir.GetPath(), "mode": p.Mkdir.GetMode()}, nil
	case *filev1.FileAssignment_Delete:
		if op != filev1.FileOperation_FILE_OPERATION_DELETE || p.Delete == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"path": p.Delete.GetPath(), "recursive": p.Delete.GetRecursive()}, nil
	case *filev1.FileAssignment_Move:
		if op != filev1.FileOperation_FILE_OPERATION_MOVE || p.Move == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"source": p.Move.GetSource(), "destination": p.Move.GetDestination(), "overwrite": p.Move.GetOverwrite()}, nil
	case *filev1.FileAssignment_Copy:
		if op != filev1.FileOperation_FILE_OPERATION_COPY || p.Copy == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"source": p.Copy.GetSource(), "destination": p.Copy.GetDestination(), "recursive": p.Copy.GetRecursive(), "overwrite": p.Copy.GetOverwrite()}, nil
	case *filev1.FileAssignment_Chmod:
		if op != filev1.FileOperation_FILE_OPERATION_CHMOD || p.Chmod == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{"path": p.Chmod.GetPath(), "mode": p.Chmod.GetMode()}, nil
	case *filev1.FileAssignment_Chown:
		if op != filev1.FileOperation_FILE_OPERATION_CHOWN || p.Chown == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		args := map[string]any{"path": p.Chown.GetPath(), "owner": p.Chown.GetOwner(), "group": p.Chown.GetGroup()}
		if p.Chown.Uid != nil {
			args["uid"] = float64(p.Chown.GetUid())
		}
		if p.Chown.Gid != nil {
			args["gid"] = float64(p.Chown.GetGid())
		}
		return args, nil
	case *filev1.FileAssignment_Search:
		if op != filev1.FileOperation_FILE_OPERATION_SEARCH || p.Search == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{
			"path":        p.Search.GetPath(),
			"query":       p.Search.GetQuery(),
			"content":     p.Search.GetContent(),
			"max_results": float64(p.Search.GetMaxResults()),
		}, nil
	case *filev1.FileAssignment_DownloadStream:
		if op != filev1.FileOperation_FILE_OPERATION_DOWNLOAD_STREAM || p.DownloadStream == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		args := map[string]any{
			"transfer_id":    p.DownloadStream.GetTransferId(),
			"transfer_token": p.DownloadStream.GetTransferToken(),
			"path":           p.DownloadStream.GetPath(),
			"offset":         p.DownloadStream.GetOffset(),
			"length":         p.DownloadStream.GetLength(),
			"chunk_index":    p.DownloadStream.GetChunkIndex(),
			"file_size":      p.DownloadStream.GetFileSize(),
		}
		if ts := p.DownloadStream.GetModifiedAt(); ts != nil && ts.IsValid() {
			args["modified_at"] = ts.AsTime().UTC().Format(time.RFC3339Nano)
		}
		return args, nil
	case *filev1.FileAssignment_UploadStream:
		if op != filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM || p.UploadStream == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{
			"path":           p.UploadStream.GetPath(),
			"offset":         p.UploadStream.GetOffset(),
			"chunk_index":    p.UploadStream.GetChunkIndex(),
			"chunk_count":    p.UploadStream.GetChunkCount(),
			"total_size":     p.UploadStream.GetTotalSize(),
			"chunk_size":     p.UploadStream.GetChunkSize(),
			"upload_id":      p.UploadStream.GetUploadId(),
			"first":          p.UploadStream.GetFirst(),
			"final":          p.UploadStream.GetFinal(),
			"transfer_id":    p.UploadStream.GetTransferId(),
			"transfer_token": p.UploadStream.GetTransferToken(),
		}, nil
	case *filev1.FileAssignment_UploadCommit:
		if op != filev1.FileOperation_FILE_OPERATION_UPLOAD_COMMIT || p.UploadCommit == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{
			"path":        p.UploadCommit.GetPath(),
			"upload_id":   p.UploadCommit.GetUploadId(),
			"chunk_index": p.UploadCommit.GetChunkIndex(),
			"chunk_count": p.UploadCommit.GetChunkCount(),
			"total_size":  p.UploadCommit.GetTotalSize(),
			"chunk_size":  p.UploadCommit.GetChunkSize(),
			"offset":      p.UploadCommit.GetOffset(),
			"first":       p.UploadCommit.GetFirst(),
			"final":       p.UploadCommit.GetFinal(),
		}, nil
	case *filev1.FileAssignment_UploadCancel:
		if op != filev1.FileOperation_FILE_OPERATION_UPLOAD_CANCEL || p.UploadCancel == nil {
			return nil, fmt.Errorf("mismatched payload for %s", op.String())
		}
		return map[string]any{
			"upload_id": p.UploadCancel.GetUploadId(),
			"path":      p.UploadCancel.GetPath(),
		}, nil
	default:
		return nil, fmt.Errorf("missing typed payload for %s", op.String())
	}
}

func execute(operation string, args map[string]any) (json.RawMessage, error) {
	return executeScoped("", operation, args)
}

func executeScoped(scope, operation string, args map[string]any) (json.RawMessage, error) {
	switch operation {
	case "list":
		return listFiles(argString(args, "path"))
	case "list_roots":
		return listFilesystemRoots()
	case "stat":
		return statFile(argString(args, "path"))
	case "create":
		return createFileWithMode(argString(args, "path"), argString(args, "mode"))
	case "mkdir":
		return mkdir(argString(args, "path"), argString(args, "mode"))
	case "delete":
		return deletePath(argString(args, "path"), argBool(args, "recursive"))
	case "move":
		return movePath(argString(args, "source"), argString(args, "destination"), argBool(args, "overwrite"))
	case "copy":
		return copyPath(argString(args, "source"), argString(args, "destination"), argBool(args, "recursive"), argBool(args, "overwrite"))
	case "chmod":
		return chmodPath(argString(args, "path"), argString(args, "mode"))
	case "chown":
		return chownPath(args)
	case "search":
		return searchFiles(args)
	case "download_stream":
		return sendDownloadStream(args)
	case "upload_stream":
		return receiveUploadStreamScoped(scope, args)
	case "upload_commit":
		return commitFileUploadScoped(scope, args)
	case "upload_cancel":
		return cancelFileUploadScoped(scope, args)
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
	case filev1.FileOperation_FILE_OPERATION_UPLOAD_COMMIT:
		return "upload_commit"
	case filev1.FileOperation_FILE_OPERATION_UPLOAD_CANCEL:
		return "upload_cancel"
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
		Size:      uint64(max(file.Size, 0)),
		Mode:      file.Mode,
		ModeOctal: file.ModeOctal,
		Uid:       int32(file.UID),
		Gid:       int32(file.GID),
		Owner:     file.Owner,
		Group:     file.Group,
		Target:    file.Target,
	}
	if !file.ModifiedAt.IsZero() {
		entry.ModifiedAt = timestamppb.New(file.ModifiedAt)
	}
	return entry
}

func decodeSearch(event *filev1.AgentFileEvent, payload json.RawMessage) {
	var decoded struct {
		Matches []searchMatch `json:"matches"`
		Limited bool          `json:"limited"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return
	}
	event.Limited = decoded.Limited
	event.Matches = make([]*filev1.SearchMatch, 0, len(decoded.Matches))
	for _, match := range decoded.Matches {
		event.Matches = append(event.Matches, &filev1.SearchMatch{
			Path:      match.Path,
			Line:      uint32(max(match.Line, 0)),
			Text:      match.Text,
			Directory: match.IsDir,
		})
	}
}
