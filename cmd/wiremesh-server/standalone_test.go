package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("the handle is invalid") }

// A service has no valid stderr; logging must still reach the file.
func TestBestEffortStderr(t *testing.T) {
	var file bytes.Buffer
	w := io.MultiWriter(bestEffort{failingWriter{}}, &file)
	if n, err := w.Write([]byte("hello\n")); err != nil || n != 6 || file.String() != "hello\n" {
		t.Fatalf("n=%d err=%v file=%q", n, err, file.String())
	}
}
