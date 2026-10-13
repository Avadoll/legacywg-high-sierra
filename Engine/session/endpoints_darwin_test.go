package session

import (
	"context"
	"testing"
	"time"
)

func TestNativeLocalhostResolution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	answers, err := systemLookup(ctx, "localhost")
	if err != nil || len(answers) == 0 {
		t.Fatal("native localhost resolution unavailable")
	}
	for _, answer := range answers {
		if !answer.Unmap().IsLoopback() {
			t.Fatal("localhost resolved outside loopback")
		}
	}
}
