package main

import (
	"net/http"
	"testing"
)

func TestTLS(t *testing.T) {
	if err := http.ListenAndServeTLS(":6060", "leaf.pem", "leaf.key", nil); err != nil {
		t.Fatal(err)
	}
}
