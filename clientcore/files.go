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
)

func (c *Client) runFileOperations(ctx context.Context) {
	executor := files.NewExecutor(ctx)
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
	go capability.CancelOnRevocation(ctx, cancel, capability.WebSSHAllowed)

	stream := c.files.AttachFileOperations(ctx)
	c.authorize(stream.RequestHeader())
	stream.RequestHeader().Set("X-Komari-Workspace-Identity", "v1")
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
	// Read the server side concurrently so grant expiry closes active workers,
	// including a long transfer, instead of waiting for the operation to finish.
	remoteClosed := make(chan struct{})
	go func() { defer close(remoteClosed); _, _ = stream.Receive(); cancel() }()

	args := map[string]any{}
	if command.GetArguments() != nil {
		for key, value := range command.GetArguments().AsMap() {
			args[key] = value
		}
	}
	putString := func(key, value string) {
		if value != "" {
			if _, exists := args[key]; !exists {
				args[key] = value
			}
		}
	}
	putString("path", command.GetPath())
	putString("destination", command.GetDestination())
	putString("source", command.GetPath())
	putString("mode", command.GetMode())
	putString("owner", command.GetOwner())
	putString("group", command.GetGroup())
	putString("query", command.GetQuery())
	if command.GetRecursive() {
		args["recursive"] = true
	}
	if command.GetOverwrite() {
		args["overwrite"] = true
	}
	if command.GetContentSearch() {
		args["content"] = true
	}
	if command.GetMaxResults() > 0 {
		args["max_results"] = float64(command.GetMaxResults())
	}

	event := executor.Execute(ctx, command.GetWorkspaceId(), command.GetSystemUser(), command.GetRequestId(), command.GetOperation(), args)
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
