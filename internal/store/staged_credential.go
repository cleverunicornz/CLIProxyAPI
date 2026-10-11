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
