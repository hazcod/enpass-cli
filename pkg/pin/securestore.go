package pin

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	fileNamePref = "enpasscli-"
	fileMode     = 0600
	kdfIterCount = 100000
	minPinLength = 8
)

type SecureStore struct {
	logger              logrus.Logger
	file                *os.File
	passphrase          []byte
	wasReadSuccessfully bool
}

func NewSecureStore(name string, pin string, logLevel logrus.Level) (*SecureStore, error) {
	var err error
	store := SecureStore{logger: *logrus.New()}
	store.logger.SetLevel(logLevel)
	store.logger.Debug("generating store passphrase from pin")
	store.passphrase, err = store.generatePassphrase(pin)
	if err != nil {
		return nil, err
	}
	store.logger.Debug("opening store")
	store.file, err = store.getStoreFile(name)
	return &store, errors.Wrap(err, "could not open store")
}

func (store *SecureStore) getStoreFile(name string) (*os.File, error) {
	var storeFile *os.File
	var err error
	storeFileName := fileNamePref + name
	for _, tempDir := range [...]string{
		os.Getenv("TMPDIR"),
		os.Getenv("XDG_RUNTIME_DIR"),
		"/dev/shm",
		os.TempDir(),
	} {
		if tempDir == "" {
			continue
		}
		store.logger.WithField("tempDir", tempDir).Debug("trying store directory")
		storeFilePath := filepath.Join(tempDir, storeFileName)
		storeFile, err = os.OpenFile(storeFilePath, os.O_CREATE, fileMode)
		if err == nil {
			break
		}
		store.logger.WithError(err).Debug("skipping store directory")
	}
	return storeFile, err
}

func (store *SecureStore) generatePassphrase(pin string) ([]byte, error) {
	if len(pin) < minPinLength {
		return nil, errors.New("PIN too short")
	}
	pepper := []byte(os.Getenv("PIN_PEPPER"))
	data := append([]byte(pin), pepper...)
	return sha256sum(data), nil
}

func (store *SecureStore) Read() ([]byte, error) {
	if store.passphrase == nil {
		return nil, errors.New("empty store passphrase")
	}
	store.logger.Debug("reading store")
	data, _ := os.ReadFile(store.file.Name())
	if data == nil || len(data) == 0 {
		return nil, nil // nothing to read
	}
	store.logger.Debug("decrypting store data")
	dbKey, err := decrypt(store.passphrase, data, kdfIterCount)
	if err != nil {
		return nil, err
	}
	store.wasReadSuccessfully = (dbKey != nil && len(dbKey) > 0)
	return dbKey, nil
}

func (store *SecureStore) Write(dbKey []byte) error {
	if store.wasReadSuccessfully {
		return nil // no need to overwrite the file if read was already successful
	}
	if store.passphrase == nil {
		return errors.New("empty store passphrase")
	}
	store.logger.Debug("encrypting store data")
	data, err := encrypt(store.passphrase, dbKey, kdfIterCount)
	if err != nil {
		return err
	}
	store.logger.Debug("writing store")
	return os.WriteFile(store.file.Name(), data, fileMode)
}

func (store *SecureStore) Clean() error {
	store.wasReadSuccessfully = false
	return os.Remove(store.file.Name())
}
