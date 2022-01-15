package enpass

import (
	"testing"

	"github.com/sirupsen/logrus"
)

const (
	testPassword = "mymasterpassword"
	vaultPath    = "../../test/"
)

func TestVault_Initialize(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}
}

func TestVault_GetEntries(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	entries, err := vault.GetEntries("password", nil)
	if err != nil {
		t.Errorf("vault get entries failed: %+v", err)
	}

	if len(entries) != 1 {
		t.Error("wrong number of entries returned")
	}
}
