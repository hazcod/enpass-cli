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

	Assert_GetEntries(t, vault, nil, 1)
}

func TestVault_GetEntries_Filter_OR(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterAnd = false

	Assert_GetEntries(t, vault, []string{"mylogin"}, 1)    // matches title
	Assert_GetEntries(t, vault, []string{"myusername"}, 1) // matches subtitle
	Assert_GetEntries(t, vault, []string{"inexistent"}, 0) // matches nothing
	Assert_GetEntries(t, vault, []string{"mylogin", "myusername"}, 1)
	Assert_GetEntries(t, vault, []string{"mylogin", "inexistent"}, 1)
	Assert_GetEntries(t, vault, []string{"inexistent", "alsoinexistent"}, 0)
}

func TestVault_GetEntries_Filter_AND(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterAnd = true

	Assert_GetEntries(t, vault, []string{"mylogin"}, 1)    // matches title
	Assert_GetEntries(t, vault, []string{"myusername"}, 1) // matches subtitle
	Assert_GetEntries(t, vault, []string{"inexistent"}, 0) // matches nothing
	Assert_GetEntries(t, vault, []string{"mylogin", "myusername"}, 1)
	Assert_GetEntries(t, vault, []string{"mylogin", "inexistent"}, 0)
	Assert_GetEntries(t, vault, []string{"inexistent", "alsoinexistent"}, 0)
}

func TestVault_GetEntries_Filter_Fields(t *testing.T) {
	vault, err := NewVault(vaultPath, logrus.ErrorLevel)
	if err != nil {
		t.Errorf("vault initialization failed: %+v", err)
	}
	defer vault.Close()
	credentials := &VaultCredentials{Password: testPassword}
	if err := vault.Open(credentials); err != nil {
		t.Errorf("opening vault failed: %+v", err)
	}

	vault.FilterAnd = false

	vault.FilterFields = []string{"title"}
	Assert_GetEntries(t, vault, []string{"mylogin"}, 1)    // matches title
	Assert_GetEntries(t, vault, []string{"myusername"}, 0) // matches subtitle
	Assert_GetEntries(t, vault, []string{"mylogin", "myusername"}, 1)

	vault.FilterFields = []string{"subtitle"}
	Assert_GetEntries(t, vault, []string{"mylogin"}, 0)    // matches title
	Assert_GetEntries(t, vault, []string{"myusername"}, 1) // matches subtitle
	Assert_GetEntries(t, vault, []string{"mylogin", "myusername"}, 1)

	vault.FilterFields = []string{"title", "subtitle"}
	Assert_GetEntries(t, vault, []string{"mylogin"}, 1)    // matches title
	Assert_GetEntries(t, vault, []string{"myusername"}, 1) // matches subtitle
	Assert_GetEntries(t, vault, []string{"mylogin", "myusername"}, 1)
}

func Assert_GetEntries(t *testing.T, vault *Vault, filters []string, expectedCount int) {
	entries, err := vault.GetEntries("password", filters)
	if err != nil {
		t.Errorf("vault get entries failed: %+v", err)
	} else if len(entries) != expectedCount {
		t.Error("wrong number of entries returned")
	}
}
