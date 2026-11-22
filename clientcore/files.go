package clientcore

import (
	"context"
	"errors"
	"log"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/files"
	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
)

const (
	fileOperationTimeout     = 5 * time.Minute
	fileStreamOperationLimit = 30 * time.Minute
	typedFilePayloadHeader   = "X-Komari-File-Payload"
)

func (c *Client) runFileOperations(ctx context.Context) {
	executor := files.NewExecutor(ctx, files.ExecutorOptions{
		AuthorizeTransfer: c.authorize,
		RootAllowed: func() bool {
			ok, _ := capability.RootExecutionAllowed()
			return ok
		},
	})
	defer executor.Close()
	semaphore := make(chan struct{}, 4)
	var retry retryPolicy
	for ctx.Err() == nil {
		if !waitForCapability(ctx, capability.WebSSHAllowed) {
			continue
		}
		req := connect.NewRequest(&filev1.LeaseFileOperationsRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		req.Header().Set("X-Komari-Workspace-Identity", "v1")
		req.Header().Set(typedFilePayloadHeader, "1")
		stream, err := c.files.LeaseFileOperations(ctx, req)
		if err != nil {
			if isUnsupported(err) || !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		received := false
		for stream.Receive() {
			received = true
			if stream.Msg().GetHeartbeat() {
				continue
			}
			assignment := stream.Msg().Assignment
			if assignment == nil {
				continue
			}
			if ok, _ := capability.WebSSHAllowed(); !ok {
				continue
			}
			select {
			case semaphore <- struct{}{}:
				go func() {
					defer func() { <-semaphore }()
					if err := c.attachFileOperation(ctx, assignment, executor); err != nil && ctx.Err() == nil {
						log.Printf("File operation failed: %v", err)
					}
				}()
			case <-ctx.Done():
				return
			}
		}
		if received {
			retry.Reset()
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			return
		}
		if !retry.Wait(ctx, stream.Err()) {
			return
		}
	}
}

func (c *Client) attachFileOperation(parent context.Context, assignment *filev1.FileAssignment, executor *files.Executor) error {
	timeout := fileOperationTimeout
	if assignment.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(assignment.GetTimeoutSeconds()) * time.Second
	}
	if assignment.GetOperation() == filev1.FileOperation_FILE_OPERATION_DOWNLOAD_STREAM ||
		assignment.GetOperation() == filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM {
		timeout = fileStreamOperationLimit
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	accountAllowed := func() (bool, string) { return capability.WebSSHAccountAllowed(assignment.GetSystemUser()) }
	if ok, reason := accountAllowed(); !ok {
		return errors.New(reason)
	}
	go capability.CancelOnRevocation(ctx, cancel, accountAllowed)

	stream := c.files.AttachFileOperations(ctx)
	c.authorize(stream.RequestHeader())
	stream.RequestHeader().Set("X-Komari-Workspace-Identity", "v1")
	stream.RequestHeader().Set(typedFilePayloadHeader, "1")
	if err := stream.Send(&filev1.AttachFileOperationsRequest{
		Message: &filev1.AttachFileOperationsRequest_Attach{Attach: &filev1.AgentFileAttach{
			AgentId:      c.agentIDValue(),
			AssignmentId: assignment.GetAssignmentId(),
			RequestId:    assignment.GetRequestId(),
		}},
	}); err != nil {
		return err
	}
	response, err := stream.Receive()
	if err != nil {
		return err
	}
	command := response.GetAssignment()
	if command == nil {
		return errors.New("file assignment is missing from the attach response")
	}
	if command.GetSystemUser() != assignment.GetSystemUser() ||
		command.GetWorkspaceId() != assignment.GetWorkspaceId() ||
		command.GetRequestId() != assignment.GetRequestId() ||
		command.GetAssignmentId() != assignment.GetAssignmentId() ||
		command.GetOperation() != assignment.GetOperation() {
		return errors.New("file assignment binding changed before attach")
	}
	// Read the server side concurrently so grant expiry closes active workers,
	// including a long transfer, instead of waiting for the operation to finish.
	remoteClosed := make(chan struct{})
	go func() { defer close(remoteClosed); _, _ = stream.Receive(); cancel() }()

	event := executor.ExecuteAssignment(ctx, command)
	event.RequestId = command.GetRequestId()
	if event.GetOperation() == filev1.FileOperation_FILE_OPERATION_UNSPECIFIED {
		event.Operation = command.GetOperation()
	}
	if err := stream.Send(&filev1.AttachFileOperationsRequest{
		Message: &filev1.AttachFileOperationsRequest_Event{Event: event},
	}); err != nil {
		return err
	}
	_ = stream.CloseRequest()
	<-remoteClosed
	return nil
}
