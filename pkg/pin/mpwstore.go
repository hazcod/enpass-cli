package pin

import (
	"os"
)

const (
  storeName = "enpasscli.mpw"
)

type MpwStore struct {
	// StoreFile : store file
	filePath string

	// storePin : store pin
	pin string
  
  WasReadSuccessfully bool
}

func (store *MpwStore) Initialize(storePin string) error {
  store.pin = storePin
  // TODO check PIN length
  path := os.Getenv("XDG_RUNTIME_DIR")
  if path == "" {
    path = os.TempDir()
  }
  store.filePath = path + "/" + storeName
  return nil
}

func (store *MpwStore) Read() (string, error) {
  data, err := os.ReadFile(store.filePath)
  if err != nil {
    return "", err
  }
  store.WasReadSuccessfully = true
  return decrypt(store.pin, string(data)), nil
}

func (store *MpwStore) Write(password string) (error) {
  data, err := encrypt(store.pin, password)
  if err != nil {
    return err
  }
  return os.WriteFile(store.filePath, []byte(data), 0600)
}
