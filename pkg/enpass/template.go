package enpass

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
)

const (
	// loginCategory is the value Enpass stores in item.category for login items.
	// The app writes it in lower case; the previous writer used "Login", which the
	// app does not recognise as a built-in category.
	loginCategory = "login"

	// loginTemplate is the value Enpass stores in item.template for login items.
	// It must not be NULL: the macOS app passes this column to strlen() while
	// rendering and crashes on a NULL template.
	loginTemplate = "login.default"
)

// templateField describes one field slot of the stock login.default template.
//
// The desktop app does not store template definitions in the vault: the
// template/category tables are empty for stock vaults and the definitions ship
// inside the app bundle (templates.json). The app resolves a field's label and
// section grouping by looking up (item.template, itemfield.item_field_uid), so
// a field written with an invented uid has no label to render.
//
// These uids and their order were taken from items written by Enpass 6.12 on
// macOS; they are stable across the 6.x releases we inspected. Fields with a
// high uid (5xxx/6xxx/9xxx) are user-created custom fields: those carry their
// label in itemfield.label and are not part of this list.
//
// A note on the hard-coded layout: the stock template is deliberately kept as a
// constant here rather than looked up, because stock vaults ship an empty
// template/category table — the definitions live in the app bundle, so there is
// nothing in the vault to read at write time. The more future-proof approach is
// to copy the skeleton from an existing item of the same template in the same
// vault (its template-provided slots are exactly the fields with an empty
// label), falling back to this constant only when the vault has no such item.
// That needs a fallback path and a policy for custom fields, so it is left as a
// follow-up rather than folded into this fix.
type templateField struct {
	// uid is Enpass's item_field_uid for this slot.
	uid int
	// fieldType is the itemfield.type value ("username", "password", ...).
	fieldType string
	// orde is the display order inside the item, starting at 1.
	orde int
	// sensitive marks fields whose value is AES-GCM encrypted with item.key.
	sensitive bool
}

// loginFields is the stock login.default layout, in display order.
var loginFields = []templateField{
	{uid: 10, fieldType: "username", orde: 1},
	{uid: 12, fieldType: "email", orde: 2},
	{uid: 11, fieldType: "password", orde: 3, sensitive: true},
	{uid: 13, fieldType: "url", orde: 4},
	{uid: 101, fieldType: "section", orde: 5},
	{uid: 14, fieldType: "phone", orde: 6},
	{uid: 102, fieldType: "totp", orde: 7},
	{uid: 15, fieldType: "text", orde: 8},
	{uid: 16, fieldType: "text", orde: 9, sensitive: true},
}

// loginFieldByType returns the first stock slot of the given type.
//
// Username, password and url have exactly one slot each, so "first" is
// unambiguous. It returns false for types the login template does not have.
//
// Example: loginFieldByType("password") == templateField{uid: 11, orde: 3, ...}, true
//
//	loginFieldByType("nope")     == templateField{}, false
func loginFieldByType(fieldType string) (templateField, bool) {
	for _, field := range loginFields {
		if field.fieldType == fieldType {
			return field, true
		}
	}

	return templateField{}, false
}

// loginIcon builds the JSON blob Enpass expects in item.icon for a login item.
//
// The app stores a JSON object, not a plain icon name. A plain string such as
// "card_password" (what the previous writer stored) makes the item render with
// a blank/default icon.
//
// The favicon domain is derived from the item URL so the app can show the site's
// icon; when the URL is empty or unparseable the favicon domain is left empty
// and the generic login icon is used.
//
// Example: loginIcon("https://www.example.com/login")
//
//	== `{"fav":"example.com","image":{"file":"misc/login"},"type":1,"uuid":""}`
func loginIcon(rawURL string) string {
	favicon := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		favicon = strings.TrimPrefix(parsed.Hostname(), "www.")
	}

	icon, err := json.Marshal(map[string]interface{}{
		"fav":   favicon,
		"image": map[string]string{"file": "misc/login"},
		"type":  1,
		"uuid":  "",
	})
	if err != nil {
		// json.Marshal of a map of strings and ints cannot fail; return the
		// generic icon rather than panicking if that ever changes.
		return `{"fav":"","image":{"file":"misc/login"},"type":1,"uuid":""}`
	}

	return string(icon)
}

// valueHash returns the SHA-1 hex digest Enpass stores in itemfield.hash.
//
// The app keeps a digest of the plaintext value (passwords included) and uses
// it to detect duplicate/identical passwords. It is empty for empty values.
//
// Example: valueHash("noIdeaata11") == "a3f1...".
func valueHash(value string) string {
	if value == "" {
		return ""
	}

	sum := sha1.Sum([]byte(value))

	return hex.EncodeToString(sum[:])
}

// valueInitial returns the two leading characters Enpass displays for a
// password field in the item list. It is only used for passwords.
//
// Example: valueInitial("agentpass") == "ag"; valueInitial("") == "".
func valueInitial(value string) string {
	runes := []rune(value)
	if len(runes) > 2 {
		return string(runes[:2])
	}

	return string(runes)
}
