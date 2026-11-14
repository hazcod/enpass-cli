package enpass

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pkg/errors"
)

type VaultInfo struct {
	EncryptionAlgo string `json:"encryption_algo"`
	HasKeyfile     int    `json:"have_keyfile"`
	KDFAlgo        string `json:"kdf_algo"`
	KDFIterations  int    `json:"kdf_iter"`
	VaultNumItems  int    `json:"vault_items_count"`
	VaultName      string `json:"vault_name"`
	VaultVersion   int    `json:"version"`
}

// loadVaultInfo : the vault info file dictates how we should decrypt the vault database
func (v *Vault) loadVaultInfo() (VaultInfo, error) {
	vaultInfoBytes, err := os.ReadFile(v.vaultInfoFilename)
	if err != nil {
		return VaultInfo{}, errors.Wrap(err, "could not read vault info")
	}

	var vaultInfo VaultInfo
	if err := json.Unmarshal(vaultInfoBytes, &vaultInfo); err != nil {
		return VaultInfo{}, errors.Wrap(err, "could not parse vault info")
	}

	v.logger.
		WithField("vault_name", vaultInfo.VaultName).
		WithField("vault_version", vaultInfo.VaultVersion).
		Debug("vault info loaded")

	return vaultInfo, nil
}

// syncVaultInfo keeps vault.json in step with the database after a write.
//
// The desktop app uses vault_items_count and last_modified_time for its own
// bookkeeping and for sync conflict detection. Leaving them stale made an entry
// created by this tool invisible to that accounting. Device and user fields
// describe whoever last wrote the vault and are left untouched.
//
// Failures are logged rather than returned: the database write is already
// committed by the time this runs, so returning an error would suggest the
// entry was not created while it actually exists.
func (v *Vault) syncVaultInfo() {
	var count int
	if err := v.db.QueryRow("SELECT count(*) FROM item WHERE deleted = 0").Scan(&count); err != nil {
		v.logger.WithError(err).Warn("could not count vault items")
		return
	}

	now := time.Now().Unix()
	err := v.patchVaultInfo(map[string]json.RawMessage{
		"vault_items_count":  json.RawMessage(strconv.Itoa(count)),
		"last_modified_time": json.RawMessage(strconv.FormatInt(now, 10)),
	})
	if err != nil {
		v.logger.WithError(err).Warn("could not update vault info")
		return
	}

	v.vaultInfo.VaultNumItems = count
}

// patchVaultInfo replaces the given keys in vault.json, leaving every other
// key byte-identical.
//
// vault.json is shared with the desktop app and the sync engine, so it carries
// fields this tool does not interpret (device names, sync watermarks, the
// encryption parameters). It is therefore decoded as raw JSON, patched, and
// written back atomically: a temporary file in the same directory followed by
// a rename, so a crash can never leave the vault described by a truncated file.
//
// Example: patchVaultInfo(map[string]json.RawMessage{"vault_items_count": json.RawMessage("2")})
func (v *Vault) patchVaultInfo(patch map[string]json.RawMessage) error {
	infoBytes, err := os.ReadFile(v.vaultInfoFilename)
	if err != nil {
		return errors.Wrap(err, "could not read vault info")
	}

	info := make(map[string]json.RawMessage)
	if err := json.Unmarshal(infoBytes, &info); err != nil {
		return errors.Wrap(err, "could not parse vault info")
	}

	for key, value := range patch {
		info[key] = value
	}

	patched, err := json.MarshalIndent(info, "", "    ")
	if err != nil {
		return errors.Wrap(err, "could not serialize vault info")
	}
	patched = append(patched, '\n')

	mode := os.FileMode(0o600)
	if stat, err := os.Stat(v.vaultInfoFilename); err == nil {
		mode = stat.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(v.vaultInfoFilename), ".vault.json.*")
	if err != nil {
		return errors.Wrap(err, "could not create temporary vault info")
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(patched); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return errors.Wrap(err, "could not write vault info")
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return errors.Wrap(err, "could not set vault info permissions")
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return errors.Wrap(err, "could not close vault info")
	}
	if err := os.Rename(tmpName, v.vaultInfoFilename); err != nil {
		os.Remove(tmpName)
		return errors.Wrap(err, "could not replace vault info")
	}

	return nil
}
