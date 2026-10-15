package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// readStagedCredential reads the credential a Save staged at path, before the
// store of record is touched. A missing or empty staging file is an error: a
// Save stores a credential and never turns into a deletion of the remote one,
// so ErrMirrorNotUpdated can only follow an actual credential write.
func readStagedCredential(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("staged credential %s is missing", path)
	}
	if err != nil {
		return nil, fmt.Errorf("read staged credential: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("staged credential %s is empty", path)
	}
	return data, nil
}

// stageExistingMirror seeds the staging file staging from the mirror file path when the mirror exists, so a
// Codex record's read-before-write merge runs against what is actually on disk. A mirror that does not exist
// leaves the staging file absent, which is how a Codex save detects a first write.
func stageExistingMirror(path, staging string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read existing auth file: %w", err)
	}
	if errWrite := os.WriteFile(staging, data, 0o600); errWrite != nil {
		return fmt.Errorf("write temp auth file: %w", errWrite)
	}
	return nil
}

// removeStagedCredential removes a Save's staging file and the Codex per-file lock file a staged Codex write
// leaves beside it, so a refused save leaves the auth directory exactly as it found it.
func removeStagedCredential(staging string) {
	_ = os.Remove(staging)
	_ = os.Remove(staging + ".lock")
}
