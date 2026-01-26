package enpass

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// sqlcipher is necessary for sqlite crypto support
	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// filename of the sqlite vault file
	vaultFileName = "vault.enpassdb"
	// contains info about your vault
	vaultInfoFileName = "vault.json"
)

// Vault : vault is the container object for vault-related operations
type Vault struct {
	// Logger : the logger instance
	logger logrus.Logger

	// settings for filtering entries
	FilterFields []string
	FilterAnd    bool

	// vault.enpassdb : SQLCipher database
	databaseFilename string

	// vault.json
	vaultInfoFilename string

	// <uuid>.enpassattach : SQLCipher database files for attachments >1KB
	//attachments []string

	// pointer to our opened database
	db *sql.DB

	// vault.json : contains info about your vault for synchronizing
	vaultInfo VaultInfo
}

type VaultCredentials struct {
	KeyfilePath string
	Password    string
	DBKey       []byte
}

func (credentials *VaultCredentials) IsComplete() bool {
	return credentials.Password != "" || credentials.DBKey != nil
}

// NewVault : Create new instance of vault and load vault info
func NewVault(vaultPath string, logLevel logrus.Level) (*Vault, error) {
	v := Vault{
		logger:       *logrus.New(),
		FilterFields: []string{"title", "subtitle"},
	}
	v.logger.SetLevel(logLevel)

	if vaultPath == "" {
		return nil, errors.New("empty vault path provided")
	}

	vaultPath, _ = filepath.EvalSymlinks(vaultPath)
	v.databaseFilename = filepath.Join(vaultPath, vaultFileName)
	v.vaultInfoFilename = filepath.Join(vaultPath, vaultInfoFileName)
	v.logger.Debug("checking provided vault paths")
	if err := v.checkPaths(); err != nil {
		return nil, err
	}

	v.logger.Debug("loading vault info")
	var err error
	v.vaultInfo, err = v.loadVaultInfo()
	if err != nil {
		return nil, errors.Wrap(err, "could not load vault info")
	}

	v.logger.
		WithField("db_path", vaultFileName).
		WithField("info_path", vaultInfoFileName).
		Debug("initialized paths")

	return &v, nil
}

func (v *Vault) openEncryptedDatabase(path string, dbKey []byte) (err error) {
	// The raw key for the sqlcipher database is given
	// by the first 64 characters of the hex-encoded key
	hexKey := hex.EncodeToString(dbKey)[:masterKeyLength]

	// Try SQLCipher v4 first (Enpass 6.8+), then fall back to v3 for older databases
	for _, cipherVersion := range []int{4, 3} {
		dbName := fmt.Sprintf(
			"%s?_pragma_key=x'%s'&_pragma_cipher_compatibility=%d",
			path,
			hexKey,
			cipherVersion,
		)

		v.db, err = sql.Open("sqlite3", dbName)
		if err != nil {
			v.logger.WithError(err).WithField("cipher_version", cipherVersion).Debug("could not open database")
			continue
		}

		// Verify the database can actually be read (key/version is correct)
		var testResult int
		if err = v.db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&testResult); err != nil {
			v.logger.WithError(err).WithField("cipher_version", cipherVersion).Debug("could not query database")
			_ = v.db.Close()
			v.db = nil
			continue
		}

		v.logger.WithField("cipher_version", cipherVersion).Debug("successfully opened database")
		return nil
	}

	return errors.New("could not open database: invalid password or unsupported database version")
}

func (v *Vault) checkPaths() error {
	if _, err := os.Stat(v.databaseFilename); os.IsNotExist(err) {
		return errors.New("vault does not exist: " + v.databaseFilename)
	}

	if _, err := os.Stat(v.vaultInfoFilename); os.IsNotExist(err) {
		return errors.New("vault info file does not exist: " + v.vaultInfoFilename)
	}

	return nil
}

func (v *Vault) generateAndSetDBKey(credentials *VaultCredentials) error {
	if credentials.DBKey != nil {
		v.logger.Debug("skipping database key generation, already set")
		return nil
	}

	if credentials.Password == "" {
		return errors.New("empty vault password provided")
	}

	if credentials.KeyfilePath == "" && v.vaultInfo.HasKeyfile == 1 {
		return errors.New("you should specify a keyfile")
	} else if credentials.KeyfilePath != "" && v.vaultInfo.HasKeyfile == 0 {
		return errors.New("you are specifying an unnecessary keyfile")
	}

	v.logger.Debug("generating master password")
	masterPassword, err := v.generateMasterPassword([]byte(credentials.Password), credentials.KeyfilePath)
	if err != nil {
		return errors.Wrap(err, "could not generate vault unlock key")
	}

	v.logger.Debug("extracting salt from database")
	keySalt, err := v.extractSalt()
	if err != nil {
		return errors.Wrap(err, "could not get master password salt")
	}

	v.logger.Debug("deriving decryption key")
	credentials.DBKey, err = v.deriveKey(masterPassword, keySalt)
	if err != nil {
		return errors.Wrap(err, "could not derive database key from master password")
	}

	return nil
}

// Open : setup a connection to the Enpass database. Call this before doing anything.
func (v *Vault) Open(credentials *VaultCredentials) error {
	v.logger.Debug("generating database key")
	if err := v.generateAndSetDBKey(credentials); err != nil {
		return errors.Wrap(err, "could not generate database key")
	}

	v.logger.Debug("opening encrypted database")
	if err := v.openEncryptedDatabase(v.databaseFilename, credentials.DBKey); err != nil {
		return errors.Wrap(err, "could not open encrypted database")
	}

	var tableName string
	err := v.db.QueryRow(`
		SELECT name
		FROM sqlite_master
		WHERE type='table' AND name='item'
	`).Scan(&tableName)
	if err != nil {
		return errors.Wrap(err, "could not connect to database")
	} else if tableName != "item" {
		return errors.New("could not connect to database")
	}

	return nil
}

// Close : close the connection to the underlying database. Always call this in the end.
func (v *Vault) Close() {
	if v.db != nil {
		err := v.db.Close()
		v.logger.WithError(err).Debug("closed vault")
	}
}

// GetEntries : return the cardType entries in the Enpass database filtered by filters.
// Note: Each item in Enpass can have multiple fields (e.g., email accounts have
// login, incoming server, outgoing server fields). This function deduplicates
// by UUID, preferring the sensitive field (typically the password).
func (v *Vault) GetEntries(cardType string, filters []string) ([]Card, error) {
	if v.db == nil || v.vaultInfo.VaultName == "" {
		return nil, errors.New("vault is not initialized")
	}

	rows, err := v.executeEntryQuery(cardType, filters)
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve cards from database")
	}

	// Use a map to deduplicate cards by UUID, keeping the sensitive field (password)
	cardMap := make(map[string]Card)

	for rows.Next() {
		var card Card

		// read the database columns into Card object
		if err := rows.Scan(
			&card.UUID, &card.Type, &card.CreatedAt, &card.UpdatedAt, &card.Title,
			&card.Subtitle, &card.Note, &card.Trashed, &card.Deleted, &card.Category,
			&card.Label, &card.value, &card.itemKey, &card.LastUsed, &card.Sensitive, &card.Icon,
		); err != nil {
			return nil, errors.Wrap(err, "could not read card from database")
		}

		card.RawValue = card.value

		// Deduplicate by UUID: prefer sensitive fields (passwords) over non-sensitive ones
		if existing, found := cardMap[card.UUID]; found {
			// Keep the new card if it's sensitive and the existing one isn't
			if card.Sensitive && !existing.Sensitive {
				cardMap[card.UUID] = card
			}
			// Otherwise keep the existing card
		} else {
			cardMap[card.UUID] = card
		}
	}

	// Convert map to slice
	cards := make([]Card, 0, len(cardMap))
	for _, card := range cardMap {
		cards = append(cards, card)
	}

	return cards, nil
}

func (v *Vault) GetEntry(cardType string, filters []string, unique bool) (*Card, error) {
	cards, err := v.GetEntries(cardType, filters)
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve cards")
	}

	var ret *Card
	for _, card := range cards {
		if card.IsTrashed() || card.IsDeleted() {
			continue
		} else if ret == nil {
			ret = &card
		} else if unique {
			return nil, errors.New("multiple cards match that title")
		} else {
			break
		}
	}

	if ret == nil {
		return nil, errors.New("card not found")
	}

	return ret, nil
}

func (v *Vault) executeEntryQuery(cardType string, filters []string) (*sql.Rows, error) {
	query := `
		SELECT uuid, type, created_at, field_updated_at, title,
		       subtitle, note, trashed, item.deleted, category,
		       label, value, key, last_used, sensitive, item.icon
		FROM item
		INNER JOIN itemfield ON uuid = item_uuid
	`

	where := []string{"item.deleted = ?"}
	values := []interface{}{0}

	if cardType != "" {
		where = append(where, "type = ?")
		values = append(values, cardType)
	}

	filterWhere := []string{}
	for _, filter := range filters {
		fq := "(0"
		for _, field := range v.FilterFields {
			fq += " + instr(lower(" + field + "), ?)"
			values = append(values, strings.ToLower(filter))
		}
		fq += " > 0)"
		filterWhere = append(filterWhere, fq)
	}

	if v.FilterAnd {
		where = append(where, filterWhere...)
	} else if len(filterWhere) > 0 {
		where = append(where, "("+strings.Join(filterWhere, " OR ")+")")
	}

	query += " WHERE " + strings.Join(where, " AND ")
	v.logger.Trace("query: ", query)
	return v.db.Query(query, values...)
}
