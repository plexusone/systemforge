package apierror

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestInternalLogsButDoesNotExposeTheError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	secret := errors.New(`pq: relation "secret_table" does not exist`)

	se := Internal(context.Background(), logger, "doing a thing", secret)
	if se.GetStatus() != 500 {
		t.Errorf("status = %d, want 500", se.GetStatus())
	}
	if strings.Contains(se.Error(), "secret_table") {
		t.Errorf("response error %q carries the internal error text", se.Error())
	}
	if !strings.Contains(buf.String(), "secret_table") || !strings.Contains(buf.String(), "doing a thing") {
		t.Errorf("log %q does not record the error and operation", buf.String())
	}
}

func TestLogNilLogger(t *testing.T) {
	// A nil logger falls back to slog.Default rather than panicking.
	Log(context.Background(), nil, "op", errors.New("boom"))
}
