package files

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pkg_flags "github.com/komari-monitor/komari-agent/cmd/flags"
	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func preserveAgentConfig(t *testing.T, endpoint string) {
	t.Helper()
	previous := *pkg_flags.GlobalConfig
	*pkg_flags.GlobalConfig = previous
	pkg_flags.GlobalConfig.Endpoint = endpoint
	pkg_flags.GlobalConfig.Token = "agent-token"
	pkg_flags.GlobalConfig.PreferIPVersion = ""
	pkg_flags.GlobalConfig.IgnoreUnsafeCert = false
	t.Cleanup(func() { *pkg_flags.GlobalConfig = previous })
}

func resetUploadStreamState(t *testing.T) {
	t.Helper()
	uploadChunksMu.Lock()
	uploadChunks = make(map[string]uploadChunkState)
	uploadChunksMu.Unlock()
	uploadLifecycleMu.Lock()
	uploadLifecycles = make(map[string]*uploadStreamLifecycle)
	uploadLifecycleMu.Unlock()
	t.Cleanup(func() {
		uploadChunksMu.Lock()
		uploadChunks = make(map[string]uploadChunkState)
		uploadChunksMu.Unlock()
		uploadLifecycleMu.Lock()
		uploadLifecycles = make(map[string]*uploadStreamLifecycle)
		uploadLifecycleMu.Unlock()
	})
}

func TestSendDownloadStreamUsesRawHTTPBody(t *testing.T) {
	data := []byte("raw download stream")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/api/clients/transfer/transfer-id" {
			t.Errorf("path = %s", request.URL.Path)
		}
		if request.URL.RawQuery != "" || request.Header.Get("X-Komari-Transfer-Token") != "relay-token" {
			t.Errorf("transfer token must only use the request header")
		}
		if request.ContentLength != int64(len(data)) {
			t.Errorf("content length = %d, want %d", request.ContentLength, len(data))
		}
		got, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		if !bytes.Equal(got, data) {
			t.Errorf("body = %q, want %q", got, data)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"received":true}`))
	}))
	defer server.Close()
	preserveAgentConfig(t, server.URL)
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := sendDownloadStream(map[string]interface{}{
		"transfer_id":    "transfer-id",
		"transfer_token": "relay-token",
		"path":           path,
		"offset":         int64(0),
		"length":         int64(len(data)),
		"file_size":      int64(len(data)),
	})
	if err != nil {
		t.Fatalf("sendDownloadStream: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result["sent"] != float64(len(data)) {
		t.Fatalf("result = %#v", result)
	}
}

func TestFileStreamClientUsesHTTP11(t *testing.T) {
	client := fileStreamHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("file stream transport must not force HTTP/2")
	}
	if len(transport.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto = %#v, want an empty map", transport.TLSNextProto)
	}
}

func TestReceiveUploadStreamWritesWithoutBufferingWholeBody(t *testing.T) {
	data := []byte("raw upload stream")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", request.Method)
		}
		writer.Header().Set("Content-Length", "17")
		_, _ = writer.Write(data)
	}))
	defer server.Close()
	preserveAgentConfig(t, server.URL)
	resetUploadStreamState(t)
	target := filepath.Join(t.TempDir(), "target.bin")
	raw, err := receiveUploadStream(map[string]interface{}{
		"transfer_id":    "transfer-id",
		"transfer_token": "relay-token",
		"path":           target,
		"upload_id":      "upload-id",
		"offset":         int64(0),
		"chunk_index":    int64(0),
		"chunk_count":    int64(1),
		"total_size":     int64(len(data)),
		"chunk_size":     int64(len(data)),
		"first":          true,
	})
	if err != nil {
		t.Fatalf("receiveUploadStream: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("receiveUploadStream returned an empty result")
	}
	partPath := uploadPartPathFor(resolveFilePath(target), "upload-id")
	got, err := os.ReadFile(partPath)
	if err != nil {
		t.Fatalf("read part file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("part = %q, want %q", got, data)
	}
}

func TestUploadStreamChunksWriteAtDistinctOffsets(t *testing.T) {
	resetUploadStreamState(t)
	root := t.TempDir()
	target := filepath.Join(root, "parallel.bin")
	first := uploadStreamSpec{
		Path:       resolveFilePath(target),
		UploadID:   "parallel-upload",
		Offset:     0,
		ChunkIndex: 0,
		ChunkCount: 3,
		TotalSize:  12,
		ChunkSize:  4,
		Expected:   4,
		First:      true,
	}
	if _, err := writeUploadStreamChunk(first, bytes.NewReader([]byte("aaaa"))); err != nil {
		t.Fatalf("write first chunk: %v", err)
	}
	second := first
	second.Offset = 4
	second.ChunkIndex = 1
	second.First = false
	third := second
	third.Offset = 8
	third.ChunkIndex = 2
	var wait sync.WaitGroup
	wait.Add(2)
	var secondErr, thirdErr error
	go func() {
		defer wait.Done()
		_, secondErr = writeUploadStreamChunk(second, bytes.NewReader([]byte("bbbb")))
	}()
	go func() {
		defer wait.Done()
		_, thirdErr = writeUploadStreamChunk(third, bytes.NewReader([]byte("cccc")))
	}()
	wait.Wait()
	if secondErr != nil || thirdErr != nil {
		t.Fatalf("parallel writes failed: second=%v third=%v", secondErr, thirdErr)
	}
	partPath := uploadPartPathFor(resolveFilePath(target), "parallel-upload")
	got, err := os.ReadFile(partPath)
	if err != nil {
		t.Fatalf("read parallel part: %v", err)
	}
	if !bytes.Equal(got, []byte("aaaabbbbcccc")) {
		t.Fatalf("part = %q, want %q", got, "aaaabbbbcccc")
	}
}

func TestFirstUploadStreamRetryPreservesOtherParts(t *testing.T) {
	resetUploadStreamState(t)
	root := t.TempDir()
	spec := uploadStreamSpec{
		Path:       resolveFilePath(filepath.Join(root, "retry.bin")),
		UploadID:   "retry-first-stream",
		ChunkIndex: 0,
		ChunkCount: 2,
		TotalSize:  8,
		ChunkSize:  4,
		Expected:   4,
		First:      true,
	}
	if _, err := writeUploadStreamChunk(spec, bytes.NewReader([]byte("1111"))); err != nil {
		t.Fatal(err)
	}
	second := spec
	second.ChunkIndex = 1
	second.Offset = 4
	second.First = false
	if _, err := writeUploadStreamChunk(second, bytes.NewReader([]byte("2222"))); err != nil {
		t.Fatal(err)
	}
	if _, err := writeUploadStreamChunk(spec, bytes.NewReader([]byte("1111"))); err != nil {
		t.Fatal(err)
	}
	partPath := uploadPartPathFor(spec.Path, spec.UploadID)
	got, err := os.ReadFile(partPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("11112222")) {
		t.Fatalf("part = %q, want %q", got, "11112222")
	}
}

func TestCommitFileUploadFinalizesRawStream(t *testing.T) {
	resetUploadStreamState(t)
	root := t.TempDir()
	target := filepath.Join(root, "committed.bin")
	spec := uploadStreamSpec{
		Path:       resolveFilePath(target),
		UploadID:   "commit-upload",
		ChunkIndex: 0,
		ChunkCount: 2,
		TotalSize:  8,
		ChunkSize:  4,
		Expected:   4,
		First:      true,
	}
	if _, err := writeUploadStreamChunk(spec, bytes.NewReader([]byte("aaaa"))); err != nil {
		t.Fatal(err)
	}
	second := spec
	second.Offset = 4
	second.ChunkIndex = 1
	second.First = false
	if _, err := writeUploadStreamChunk(second, bytes.NewReader([]byte("bbbb"))); err != nil {
		t.Fatal(err)
	}

	result, err := commitFileUpload(map[string]interface{}{
		"path":        target,
		"upload_id":   spec.UploadID,
		"chunk_count": int64(spec.ChunkCount),
		"total_size":  int64(spec.TotalSize),
		"chunk_size":  int64(spec.ChunkSize),
	})
	if err != nil {
		t.Fatalf("commitFileUpload: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("commitFileUpload returned an empty result")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("aaaabbbb")) {
		t.Fatalf("committed content = %q", got)
	}
	if _, err := os.Stat(uploadPartPathFor(spec.Path, spec.UploadID)); !os.IsNotExist(err) {
		t.Fatalf("part file still exists after commit: %v", err)
	}
}

func TestCancelUploadStreamsPreventsLateStreamRegistration(t *testing.T) {
	resetUploadStreamState(t)
	cancelUploadStreams("cancel-before-start")
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := beginUploadStream("cancel-before-start", "late-stream", cancel); err == nil {
		t.Fatal("late upload stream registration was accepted after cancellation")
	}
}

func TestCancelUploadStreamsInterruptsActiveStream(t *testing.T) {
	resetUploadStreamState(t)
	ctx, cancel := context.WithCancel(context.Background())
	end, err := beginUploadStream("cancel-active", "active-stream", cancel)
	if err != nil {
		t.Fatal(err)
	}
	cancelUploadStreams("cancel-active")
	select {
	case <-ctx.Done():
	default:
		t.Fatal("active upload stream was not canceled")
	}
	end()
	waitUploadStreams("cancel-active")
}

func TestUploadManifestSurvivesWorkerEvictionAndEnforcesWorkspaceScope(t *testing.T) {
	resetUploadStreamState(t)
	root := t.TempDir()
	target := filepath.Join(root, "resumed.bin")
	spec := uploadStreamSpec{
		WorkspaceID: "ws-alpha",
		Path:        resolveFilePath(target),
		UploadID:    "persisted-upload",
		ChunkIndex:  0,
		ChunkCount:  2,
		TotalSize:   8,
		ChunkSize:   4,
		Expected:    4,
		First:       true,
	}
	if _, err := writeUploadStreamChunk(spec, bytes.NewReader([]byte("part"))); err != nil {
		t.Fatalf("chunk 0 failed: %v", err)
	}
	manifestPath := uploadManifestPathFor(spec.Path, spec.UploadID)
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected persisted upload manifest at %s: %v", manifestPath, err)
	}

	// Simulate 3-minute idle eviction discarding all in-memory chunk state.
	uploadChunksMu.Lock()
	uploadChunks = make(map[string]uploadChunkState)
	uploadChunksMu.Unlock()

	// Another workspace must NOT resume or commit the persisted upload.
	wrongSecond := spec
	wrongSecond.WorkspaceID = "ws-beta"
	wrongSecond.Offset = 4
	wrongSecond.ChunkIndex = 1
	wrongSecond.First = false
	if _, err := writeUploadStreamChunk(wrongSecond, bytes.NewReader([]byte("-two"))); err == nil {
		t.Fatal("other workspace resumed persisted upload")
	}

	// Same workspace resumes cleanly after memory wipe.
	second := spec
	second.Offset = 4
	second.ChunkIndex = 1
	second.First = false
	if _, err := writeUploadStreamChunk(second, bytes.NewReader([]byte("-two"))); err != nil {
		t.Fatalf("chunk 1 after memory eviction failed: %v", err)
	}

	// Simulate another idle eviction before upload_commit.
	uploadChunksMu.Lock()
	uploadChunks = make(map[string]uploadChunkState)
	uploadChunksMu.Unlock()

	if _, err := commitFileUploadScoped("ws-beta", map[string]any{
		"path":        target,
		"upload_id":   spec.UploadID,
		"chunk_count": int64(2),
		"total_size":  int64(8),
		"chunk_size":  int64(4),
	}); err == nil {
		t.Fatal("other workspace committed persisted upload")
	}

	if _, err := commitFileUploadScoped("ws-alpha", map[string]any{
		"path":        target,
		"upload_id":   spec.UploadID,
		"chunk_count": int64(2),
		"total_size":  int64(8),
		"chunk_size":  int64(4),
	}); err != nil {
		t.Fatalf("commit after memory eviction failed: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil || string(got) != "part-two" {
		t.Fatalf("committed target = %q err=%v, want %q", got, err, "part-two")
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("manifest still exists after commit: %v", err)
	}
}

func TestUploadManifestWriteFailureDoesNotAcknowledgeChunk(t *testing.T) {
	resetUploadStreamState(t)
	spec := uploadStreamSpec{
		Path: filepath.Join(t.TempDir(), "retry.bin"), UploadID: "failed-manifest",
		ChunkCount: 1, TotalSize: 4, ChunkSize: 4, Expected: 4, First: true,
	}
	manifestPath := uploadManifestPathFor(spec.Path, spec.UploadID)
	if err := os.Mkdir(filepath.Dir(manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(manifestPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := writeUploadStreamChunk(spec, bytes.NewReader([]byte("data"))); err == nil {
		t.Fatal("chunk was accepted without a durable manifest")
	}
	args := map[string]any{"path": spec.Path, "upload_id": spec.UploadID, "chunk_count": int64(1), "total_size": int64(4), "chunk_size": int64(4)}
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	if _, err := commitFileUpload(args); err == nil {
		t.Fatal("commit accepted a chunk whose manifest write failed")
	}
	if _, err := writeUploadStreamChunk(spec, bytes.NewReader([]byte("data"))); err != nil {
		t.Fatal(err)
	}
	if _, err := commitFileUpload(args); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteAssignmentTypedPayloadAndRejectsUnderscoreOp(t *testing.T) {
	resetUploadStreamState(t)
	root := t.TempDir()
	path := filepath.Join(root, "typed.txt")

	created := ExecuteAssignment(&filev1.FileAssignment{
		RequestId:   "req-create",
		WorkspaceId: "ws-typed",
		Operation:   filev1.FileOperation_FILE_OPERATION_CREATE,
		Payload: &filev1.FileAssignment_Create{Create: &filev1.FileCreatePayload{
			Path: path,
			Mode: "0600",
		}},
	})
	if !created.GetSuccess() || created.GetRequestId() != "req-create" {
		t.Fatalf("typed create failed: %+v", created)
	}

	// Mismatched operation vs payload variant must fail.
	mismatch := ExecuteAssignment(&filev1.FileAssignment{
		RequestId: "req-mismatch",
		Operation: filev1.FileOperation_FILE_OPERATION_STAT,
		Payload:   &filev1.FileAssignment_List{List: &filev1.FileListPayload{Path: root}},
	})
	if mismatch.GetSuccess() {
		t.Fatal("mismatched operation and typed payload succeeded")
	}

	// Legacy _op override in Execute must be ignored cleanly.
	noOpOverride := Execute(filev1.FileOperation_FILE_OPERATION_STAT, map[string]any{
		"_op":  "delete",
		"path": path,
	})
	if !noOpOverride.GetSuccess() {
		t.Fatalf("stat with ignored _op failed: %+v", noOpOverride)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("_op=delete deleted file unexpectedly: %v", err)
	}
}

func TestLegacyAssignmentOnlyAcceptsTheKnownWireShapes(t *testing.T) {
	for _, check := range []struct {
		enum filev1.FileOperation
		name string
		want filev1.FileOperation
		ok   bool
	}{
		{filev1.FileOperation_FILE_OPERATION_STAT, "stat", filev1.FileOperation_FILE_OPERATION_STAT, true},
		{filev1.FileOperation_FILE_OPERATION_STAT, "delete", 0, false},
		{filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM, "upload_commit", filev1.FileOperation_FILE_OPERATION_UPLOAD_COMMIT, true},
		{filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM, "upload_cancel", filev1.FileOperation_FILE_OPERATION_UPLOAD_CANCEL, true},
	} {
		args, err := structpb.NewStruct(map[string]any{"_op": check.name, "path": "/tmp/test"})
		if err != nil {
			t.Fatal(err)
		}
		op, decoded, err := decodeAssignment(&filev1.FileAssignment{Operation: check.enum, Arguments: args})
		if (err == nil) != check.ok || (check.ok && (op != check.want || decoded["_op"] != nil)) {
			t.Errorf("decode %s/%s = %s, %#v, %v", check.enum, check.name, op, decoded, err)
		}
	}
}
