package enpass

import (
	"encoding/hex"
	"encoding/xml"
	"os"

	"github.com/pkg/errors"
)

type Keyfile struct {
	Key string `xml:",innerxml"`
}

func loadKeyFilePassword(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "could not load keyfile")
	}

	var kf Keyfile
	if err := xml.Unmarshal(bytes, &kf); err != nil {
		return nil, errors.Wrap(err, "could not decode keyfile")
	}

	keyBytes, err := hex.DecodeString(kf.Key)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode keyfile hex byte")
	}

	return keyBytes, nil
}
