package main

import (
	"io"
	"strings"
	"testing"
)

func TestAcceptRollbackNeedsConfirm(t *testing.T) {
	cmd := newRootCmdWithOptions(&options{})
	cmd.SetArgs([]string{"keys", "accept-rollback"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("accept-rollback without --confirm: %v", err)
	}
}
