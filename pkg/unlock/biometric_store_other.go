//go:build !darwin
// +build !darwin

package unlock

import (
	"errors"

	"github.com/sirupsen/logrus"
)

type BiometricStore struct{}

func NewBiometricStore(_ string, _ logrus.Level) (*BiometricStore, error) {
	return nil, errors.New("biometric unlock is only supported on macOS")
}

func (store *BiometricStore) Read() ([]byte, error) {
	return nil, errors.New("biometric unlock is only supported on macOS")
}

func (store *BiometricStore) Write(_ []byte) error {
	return errors.New("biometric unlock is only supported on macOS")
}

func (store *BiometricStore) Clean() error {
	return errors.New("biometric unlock is only supported on macOS")
}
