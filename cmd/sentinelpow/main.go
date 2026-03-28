package main

import (
	"encoding/json"
	"fmt"
	"os"

	"codex/internal/sentinel"
)

func main() {
	var req sentinel.Request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(sentinel.Response{Error: fmt.Sprintf("decode request: %v", err)})
		os.Exit(1)
	}

	resp, err := sentinel.Run(req)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(sentinel.Response{Error: err.Error()})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}
