package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/hazcod/enpass-cli/pkg/clipboard"
	"github.com/hazcod/enpass-cli/pkg/enpass"
	"github.com/hazcod/enpass-cli/pkg/unlock"
	"github.com/miquella/ask"
	"github.com/rivo/tview"
	"github.com/sirupsen/logrus"
)

const (
	// commands
	cmdVersion = "version"
	cmdHelp    = "help"
	cmdDryRun  = "dryrun"
	cmdList    = "list"
	cmdShow    = "show"
	cmdCopy    = "copy"
	cmdPass    = "pass"
	cmdUi      = "ui"
	cmdCreate  = "create"
	cmdEdit    = "edit"
	cmdTrash   = "trash"
	cmdRestore = "restore"
	cmdDelete  = "delete"
	cmdEnv     = "env"

	// defaults
	defaultLogLevel        = logrus.InfoLevel
	pinMinLength           = 8
	pinDefaultKdfIterCount = 100000
)

var (
	// overwritten by go build
	version = "dev"
	// set of all commands
	commands = map[string]struct{}{
		cmdVersion: {}, cmdHelp: {}, cmdDryRun: {}, cmdList: {},
		cmdShow: {}, cmdCopy: {}, cmdPass: {}, cmdUi: {},
		cmdCreate: {}, cmdEdit: {}, cmdTrash: {}, cmdRestore: {}, cmdDelete: {}, cmdEnv: {},
	}
)

type Args struct {
	command string
	// params
	filters []string
	// flags
	vaultPath        *string
	cardType         *string
	keyFilePath      *string
	logLevelStr      *string
	jsonOutput       *bool
	nonInteractive   *bool
	pinEnable        *bool
	sort             *bool
	trashed          *bool
	detailed         *bool
	and              *bool
	clipboardPrimary *bool
	field            *string
	// write command flags
	title    *string
	login    *string
	password *string
	url      *string
	notes    *string
	category *string
	force    *bool
}

func (args *Args) parse() {
	args.vaultPath = flag.String("vault", "", "Path to your Enpass vault.")
	args.cardType = flag.String("type", "password", "The type of your card. (password, ...)")
	args.keyFilePath = flag.String("keyfile", "", "Path to your Enpass vault keyfile.")
	args.logLevelStr = flag.String("log", defaultLogLevel.String(), "The log level: trace, debug, info, warn, error, fatal, panic.")
	args.jsonOutput = flag.Bool("json", false, "Output data in JSON format.")
	args.nonInteractive = flag.Bool("nonInteractive", false, "Disable prompts and fail instead.")
	args.pinEnable = flag.Bool("pin", false, "Enable PIN.")
	args.and = flag.Bool("and", false, "Combines filters with AND instead of default OR.")
	args.sort = flag.Bool("sort", false, "Sort the output by title and username of the 'list' and 'show' command.")
	args.trashed = flag.Bool("trashed", false, "Show trashed items in the 'list' and 'show' command.")
	args.detailed = flag.Bool("detailed", false, "Show every field of each entry in 'list' and 'show'. Without this flag, only the original summary fields (title, login, category, label, type) are displayed.")
	args.clipboardPrimary = flag.Bool("clipboardPrimary", false, "Use primary X selection instead of clipboard for the 'copy' command.")
	args.field = flag.String("field", "", "Field label to extract (default: password). Used with 'env' command.")
	// write command flags
	args.title = flag.String("title", "", "Entry title (for create/edit).")
	args.login = flag.String("login", "", "Username or email (for create/edit).")
	args.password = flag.String("password", "", "Password (for create/edit). Prompts if flag present without value.")
	args.url = flag.String("url", "", "URL (for create/edit).")
	args.notes = flag.String("notes", "", "Notes (for create/edit).")
	args.category = flag.String("category", "", "Category (for create/edit).")
	args.force = flag.Bool("force", false, "Skip confirmation prompts.")
	flag.Parse()
	args.command = strings.ToLower(flag.Arg(0))
	if len(flag.Args()) > 1 {
		args.filters = flag.Args()[1:]
	} else {
		args.filters = []string{}
	}
}

func prompt(logger *logrus.Logger, args *Args, msg string) string {
	if !*args.nonInteractive {
		if response, err := ask.HiddenAsk("Enter " + msg + ": "); err != nil {
			logger.WithError(err).Fatal("could not prompt for " + msg)
		} else {
			return response
		}
	}
	return ""
}

func printHelp() {
	fmt.Println("Usage: enpass-cli [flags] <command> [filters...]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  list [filter]     List entries (without passwords; TOTP fields masked)")
	fmt.Println("  show [filter]     Show entries (with passwords; computes RFC 6238 TOTP code)")
	fmt.Println("  copy <filter>     Copy password to clipboard")
	fmt.Println("  pass <filter>     Print password to stdout")
	fmt.Println("  env VARNAME=filter  Output entry field as KEY=VALUE for shell eval")
	fmt.Println("  ui                Interactive terminal UI")
	fmt.Println("  create            Create a new entry")
	fmt.Println("  edit <filter>     Edit an existing entry")
	fmt.Println("  trash <filter>    Move entry to trash")
	fmt.Println("  restore <filter>  Restore entry from trash")
	fmt.Println("  delete <filter>   Permanently delete entry")
	fmt.Println("  dryrun            Test vault opening")
	fmt.Println("  version           Print version")
	fmt.Println("  help              Print this help")
	fmt.Println()
	fmt.Println("Pass -detailed to list/show to see every field of each entry instead of")
	fmt.Println("only the summary fields (title, login, category, label, type). TOTP fields")
	fmt.Println("are treated as sensitive: their secret is hidden in list, and show prints")
	fmt.Println("the current RFC 6238 code alongside the secret.")
	fmt.Println()
	fmt.Println("The env command outputs vault values as shell-safe KEY='value' lines.")
	fmt.Println("Use -field to select a specific field label (default: password).")
	fmt.Println("  eval $(enpass-cli -vault /path env MY_SECRET=\"entry title\")")
	fmt.Println("  eval $(enpass-cli -vault /path env -field \"Access Key\" AWS_KEY=\"AWS\")")
	fmt.Println()
	fmt.Println("Flags:")
	flag.Usage()
}

func sortEntries(cards []enpass.Card) {
	// Sort by username preserving original order
	sort.SliceStable(cards, func(i, j int) bool {
		return strings.ToLower(cards[i].Subtitle) < strings.ToLower(cards[j].Subtitle)
	})
	// Sort by title, preserving username order
	sort.SliceStable(cards, func(i, j int) bool {
		return strings.ToLower(cards[i].Title) < strings.ToLower(cards[j].Title)
	})
}

func listEntries(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	entries, err := collectEntries(vault, args, false)
	if err != nil {
		logger.WithError(err).Fatal(err.Error())
	}
	outputEntriesOrLog(logger, entries, args)
}

func showEntries(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	entries, err := collectEntries(vault, args, true)
	if err != nil {
		logger.WithError(err).Fatal(err.Error())
	}
	outputEntriesOrLog(logger, entries, args)
}

// entryView is one Enpass item with all of its fields grouped together.
type entryView struct {
	UUID     string       `json:"uuid"`
	Title    string       `json:"title"`
	Subtitle string       `json:"subtitle,omitempty"`
	Category string       `json:"category,omitempty"`
	Trashed  bool         `json:"trashed,omitempty"`
	Fields   []fieldView  `json:"fields"`
}

// fieldView is a single field of an entry (username, email, password, ...).
// Value is empty when the field is sensitive and the caller didn't ask for
// decrypted output (list mode). For TOTP fields the stored Value is the
// secret key, so it's treated as sensitive: hidden in list mode, included in
// show mode. TOTPCode carries the current RFC 6238 code; TOTPError is set
// when computing it failed.
type fieldView struct {
	Type      string `json:"type"`
	Label     string `json:"label,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
	Value     string `json:"value,omitempty"`
	TOTPCode  string `json:"totp_code,omitempty"`
	TOTPError string `json:"totp_error,omitempty"`
}

// collectEntries fetches every field for matching entries and groups them by
// item UUID. When includeSensitive is false, values of sensitive fields
// (passwords) are omitted while non-sensitive fields like username/email are
// still populated — this is what powers the "list shows usernames and emails
// but not passwords" behavior.
func collectEntries(vault *enpass.Vault, args *Args, includeSensitive bool) ([]entryView, error) {
	// The -type flag defaults to "password" for the copy/pass commands. For
	// list/show we want every field type, so treat the default as "no filter".
	// Any other explicit value still filters server-side.
	typeFilter := *args.cardType
	if typeFilter == "password" {
		typeFilter = ""
	}

	cards, err := vault.GetAllFields(typeFilter, args.filters)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve cards: %w", err)
	}

	order := make([]string, 0)
	groups := make(map[string]*entryView)
	for _, c := range cards {
		if c.IsDeleted() {
			continue
		}
		if c.IsTrashed() && !*args.trashed {
			continue
		}
		// Non-password field values are stored in cleartext; Decrypt() returns
		// them as-is. For password fields, Decrypt() actually decrypts.
		value, derr := c.Decrypt()
		if derr != nil {
			return nil, fmt.Errorf("could not decrypt %s/%s: %w", c.Title, c.Label, derr)
		}
		// Match the Enpass native apps' view mode: hide empty-value template
		// placeholders that a user never filled in (e.g. "Date Mod", "Field 6").
		// Sections are visual dividers and stay even when empty.
		if value == "" && c.Type != "section" {
			continue
		}
		g, ok := groups[c.UUID]
		if !ok {
			g = &entryView{
				UUID:     c.UUID,
				Title:    c.Title,
				Subtitle: c.Subtitle,
				Category: c.Category,
				Trashed:  c.IsTrashed(),
			}
			groups[c.UUID] = g
			order = append(order, c.UUID)
		}
		f := fieldView{
			Type:      c.Type,
			Label:     c.Label,
			Sensitive: c.Sensitive,
		}
		isTOTP := c.Type == "totp"
		hasValue := value != ""
		// TOTP fields are classified as sensitive: in list mode neither the
		// secret nor the live code is exposed. Only compute the code when the
		// caller is going to display it.
		if isTOTP && hasValue && includeSensitive {
			if code, terr := enpass.ComputeTOTP(value, time.Now()); terr == nil {
				f.TOTPCode = code
			} else {
				f.TOTPError = terr.Error()
			}
		}
		if isTOTP && hasValue {
			f.Sensitive = true
		}
		if includeSensitive || !f.Sensitive {
			f.Value = value
		}
		g.Fields = append(g.Fields, f)
	}

	entries := make([]entryView, 0, len(order))
	for _, uuid := range order {
		entries = append(entries, *groups[uuid])
	}
	if *args.sort {
		sort.SliceStable(entries, func(i, j int) bool {
			return strings.ToLower(entries[i].Title) < strings.ToLower(entries[j].Title)
		})
	}
	return entries, nil
}

func outputEntriesOrLog(logger *logrus.Logger, entries []entryView, args *Args) {
	if *args.detailed {
		outputDetailed(logger, entries, args)
		return
	}
	outputCompact(logger, entries, args)
}

// outputCompact reproduces the original list/show output: one row per entry
// with the summary fields title, login, category, label, type — plus password
// when present (show mode).
func outputCompact(logger *logrus.Logger, entries []entryView, args *Args) {
	type compactRow struct {
		Title    string `json:"title"`
		Login    string `json:"login"`
		Category string `json:"category"`
		Label    string `json:"label"`
		Type     string `json:"type"`
		Password string `json:"password,omitempty"`
	}

	rows := make([]compactRow, 0, len(entries))
	for _, e := range entries {
		anchor := anchorField(e.Fields)
		row := compactRow{
			Title:    e.Title,
			Login:    e.Subtitle,
			Category: e.Category,
		}
		if anchor != nil {
			row.Label = anchor.Label
			row.Type = anchor.Type
			if anchor.Sensitive {
				row.Password = anchor.Value
			}
		}
		rows = append(rows, row)
	}

	if *args.jsonOutput {
		jsonData, err := json.Marshal(rows)
		if err != nil {
			logger.WithError(err).Fatal("could not marshal JSON data")
		}
		fmt.Println(string(jsonData))
		return
	}
	for _, r := range rows {
		format := "> title: %s  login: %s  cat.: %s  label: %s  type: %s"
		vals := []any{r.Title, r.Login, r.Category, r.Label, r.Type}
		if r.Password != "" {
			format += "  password: %s"
			vals = append(vals, r.Password)
		}
		logger.Printf(format, vals...)
	}
}

// outputDetailed emits the grouped per-field view: one header line per entry
// followed by an indented line per field.
func outputDetailed(logger *logrus.Logger, entries []entryView, args *Args) {
	if *args.jsonOutput {
		jsonData, err := json.Marshal(entries)
		if err != nil {
			logger.WithError(err).Fatal("could not marshal JSON data")
		}
		fmt.Println(string(jsonData))
		return
	}
	for _, e := range entries {
		header := "> " + e.Title
		if e.Subtitle != "" {
			header += "  (" + e.Subtitle + ")"
		}
		if e.Category != "" {
			header += "  cat.: " + e.Category
		}
		if e.Trashed {
			header += "  [trashed]"
		}
		logger.Print(header)
		for _, f := range e.Fields {
			name := f.Label
			if name == "" {
				name = f.Type
			}
			// Three-level hierarchy: record header (no indent), section header
			// (4 spaces), regular field (8 spaces). Regular fields are at the
			// same depth whether the record has sections or not, so columns
			// stay aligned across records.
			indent := fieldIndent
			if f.Type == "section" {
				indent = sectionIndent
			}
			if f.Type == "totp" && (f.TOTPCode != "" || f.TOTPError != "") {
				renderTOTPField(logger, indent, name, f)
				continue
			}
			switch {
			case f.Sensitive && f.Value == "":
				logger.Printf("%s%s (%s): ********", indent, name, f.Type)
			case f.Value != "":
				logger.Printf("%s%s (%s): %s", indent, name, f.Type, f.Value)
			default:
				logger.Printf("%s%s (%s)", indent, name, f.Type)
			}
		}
	}
}

const (
	sectionIndent = "    "
	fieldIndent   = "        "
)

// renderTOTPField prints a TOTP field. When the code could be computed we
// show it; otherwise we tell the user the value is dynamic. The secret is
// only included when collectEntries chose to expose it (i.e. show mode).
func renderTOTPField(logger *logrus.Logger, indent, name string, f fieldView) {
	parts := []string{}
	switch {
	case f.TOTPCode != "":
		parts = append(parts, "code "+f.TOTPCode)
	case f.TOTPError != "":
		parts = append(parts, "<dynamic TOTP value>")
	default:
		logger.Printf("%s%s (%s)", indent, name, f.Type)
		return
	}
	if f.Value != "" {
		parts = append(parts, "secret: "+f.Value)
	}
	logger.Printf("%s%s (%s): %s", indent, name, f.Type, strings.Join(parts, "  "))
}

// anchorField picks the field that represents the entry in compact mode.
// Prefer the password field so the compact summary stays password-focused
// even when other sensitive field types (e.g. TOTP) are present. Fall back
// to any sensitive field, then to the first field.
func anchorField(fields []fieldView) *fieldView {
	for i := range fields {
		if fields[i].Type == "password" {
			return &fields[i]
		}
	}
	for i := range fields {
		if fields[i].Sensitive {
			return &fields[i]
		}
	}
	if len(fields) > 0 {
		return &fields[0]
	}
	return nil
}

func copyEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	card, err := vault.GetEntry(*args.cardType, args.filters, true)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve unique card")
	}

	decrypted, err := card.Decrypt()
	if err != nil {
		logger.WithError(err).Fatal("could not decrypt card")
	}

	if *args.clipboardPrimary {
		clipboard.Primary = true
		logger.Debug("primary X selection enabled")
	}

	if err := clipboard.WriteAll(decrypted); err != nil {
		logger.WithError(err).Fatal("could not copy password to clipboard")
	}
}

func entryPassword(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	card, err := vault.GetEntry(*args.cardType, args.filters, true)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve unique card")
	}

	if decrypted, err := card.Decrypt(); err != nil {
		logger.WithError(err).Fatal("could not decrypt card")
	} else {
		fmt.Println(decrypted)
	}
}

func envEntries(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	if len(args.filters) == 0 {
		logger.Fatal("env command requires at least one VARNAME=filter argument")
	}

	var jsonResult map[string]string
	if *args.jsonOutput {
		jsonResult = make(map[string]string, len(args.filters))
	}

	for _, arg := range args.filters {
		eqIdx := strings.Index(arg, "=")
		if eqIdx < 1 {
			logger.Fatalf("invalid argument %q: expected VARNAME=filter", arg)
		}

		varName := arg[:eqIdx]
		filter := arg[eqIdx+1:]

		for _, r := range varName {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
				logger.Fatalf("invalid variable name %q: must contain only letters, digits, and underscores", varName)
			}
		}
		if varName[0] >= '0' && varName[0] <= '9' {
			logger.Fatalf("invalid variable name %q: must not start with a digit", varName)
		}

		var value string

		if *args.field == "" {
			card, err := vault.GetEntry(*args.cardType, []string{filter}, true)
			if err != nil {
				logger.WithError(err).Fatalf("could not retrieve entry for %s", varName)
			}

			decrypted, err := card.Decrypt()
			if err != nil {
				logger.WithError(err).Fatalf("could not decrypt entry for %s", varName)
			}

			value = decrypted
		} else {
			typeFilter := *args.cardType
			if typeFilter == "password" {
				typeFilter = ""
			}

			cards, err := vault.GetAllFields(typeFilter, []string{filter})
			if err != nil {
				logger.WithError(err).Fatalf("could not retrieve fields for %s", varName)
			}

			// Group by entry UUID and enforce uniqueness.
			entries := make(map[string][]enpass.Card)
			var order []string
			for _, c := range cards {
				if c.IsDeleted() || c.IsTrashed() {
					continue
				}
				if _, seen := entries[c.UUID]; !seen {
					order = append(order, c.UUID)
				}
				entries[c.UUID] = append(entries[c.UUID], c)
			}

			if len(entries) == 0 {
				logger.Fatalf("no entry found matching filter for %s", varName)
			}
			if len(entries) > 1 {
				logger.Fatalf("multiple entries match filter for %s, refine your filter", varName)
			}

			// Find the field matching -field label.
			fields := entries[order[0]]
			var match *enpass.Card
			for i, c := range fields {
				if strings.EqualFold(c.Label, *args.field) {
					match = &fields[i]
					break
				}
			}

			if match == nil {
				logger.Fatalf("no field %q found in entry for %s", *args.field, varName)
			}

			decrypted, err := match.Decrypt()
			if err != nil {
				logger.WithError(err).Fatalf("could not decrypt field %q for %s", *args.field, varName)
			}

			value = decrypted
		}

		if jsonResult != nil {
			jsonResult[varName] = value
		} else {
			fmt.Printf("%s='%s'\n", varName, shellQuote(value))
		}
	}

	if jsonResult != nil {
		jsonData, err := json.Marshal(jsonResult)
		if err != nil {
			logger.WithError(err).Fatal("could not marshal JSON output")
		}
		fmt.Println(string(jsonData))
	}
}

func shellQuote(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

func ui(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	cards, err := vault.GetEntries(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve cards")
	}
	if *args.sort {
		sortEntries(cards)
	}

	app := tview.NewApplication()
	flex := tview.NewFlex().SetDirection(tview.FlexRow)
	table := tview.NewTable().SetBorders(false)
	flex.AddItem(table, 0, 1, true)

	var visibleCards []enpass.Card
	render := func(filter string) {
		filter = strings.ToLower(filter)
		visibleCards = []enpass.Card{}

		table.Clear()
		table.SetCell(0, 0, tview.NewTableCell("Title").SetBackgroundColor(tcell.ColorGray))
		table.SetCell(0, 1, tview.NewTableCell("Subtitle").SetBackgroundColor(tcell.ColorGray))
		table.SetCell(0, 2, tview.NewTableCell("Category").SetBackgroundColor(tcell.ColorGray))

		i := 0
		for _, card := range cards {
			if card.IsTrashed() && !*args.trashed {
				continue
			}
			if !strings.Contains(strings.ToLower(card.Title+" "+card.Subtitle), filter) {
				continue
			}

			table.SetCell(i+1, 0, tview.NewTableCell(card.Title))
			table.SetCell(i+1, 1, tview.NewTableCell(card.Subtitle))
			table.SetCell(i+1, 2, tview.NewTableCell(card.Category))
			i += 1
			visibleCards = append(visibleCards, card)
		}
	}
	render("") // render ininital table without filter

	statusText := tview.NewTextView().SetChangedFunc(func() {
		app.Draw()
	})

	inputField := tview.NewInputField()
	inputField.SetLabel("Search: ").
		SetFieldWidth(30).
		SetDoneFunc(func(key tcell.Key) {
			render(inputField.GetText())
			app.SetFocus(table)
			statusText.SetText(fmt.Sprintf("found %d", len(visibleCards)))
		})

	status := tview.NewFlex()
	status.AddItem(inputField, 0, 1, false)
	status.AddItem(statusText, 0, 1, false)
	flex.AddItem(status, 1, 1, false)

	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == '/' {
			app.SetFocus(inputField)
		}
		return event
	})

	table.Select(0, 0).SetFixed(1, 1)
	table.SetSelectable(true, false)
	table.SetSelectedFunc(func(row int, column int) {
		card := visibleCards[row-1]
		if decrypted, err := card.Decrypt(); err != nil {
			logger.WithError(err).Fatal("could not decrypt card")
		} else {
			if err := clipboard.WriteAll(decrypted); err != nil {
				logger.WithError(err).Fatal("could not copy password to clipboard")
			} else {
				statusText.SetText("copied password for " + card.Title)
			}
		}
	})

	if err := app.SetRoot(flex, true).SetFocus(inputField).Run(); err != nil {
		panic(err)
	}
}

func assembleVaultCredentials(logger *logrus.Logger, args *Args, store *unlock.SecureStore) *enpass.VaultCredentials {
	credentials := &enpass.VaultCredentials{
		Password:    os.Getenv("MASTERPW"),
		KeyfilePath: *args.keyFilePath,
	}

	if !credentials.IsComplete() && store != nil {
		var err error
		if credentials.DBKey, err = store.Read(); err != nil {
			logger.WithError(err).Fatal("could not read credentials from store")
		}
		logger.Debug("read credentials from store")
	}

	if !credentials.IsComplete() {
		credentials.Password = prompt(logger, args, "vault password")
	}

	return credentials
}

func initializeStore(logger *logrus.Logger, args *Args) *unlock.SecureStore {
	vaultPath, _ := filepath.EvalSymlinks(*args.vaultPath)
	store, err := unlock.NewSecureStore(filepath.Base(vaultPath), logger.Level)
	if err != nil {
		logger.WithError(err).Fatal("could not create store")
	}

	pin := os.Getenv("ENP_PIN")
	if pin == "" {
		pin = prompt(logger, args, "PIN")
	}
	if len(pin) < pinMinLength {
		logger.Fatal("PIN too short")
	}

	pepper := os.Getenv("ENP_PIN_PEPPER")

	pinKdfIterCount, err := strconv.ParseInt(os.Getenv("ENP_PIN_ITER_COUNT"), 10, 32)
	if err != nil {
		pinKdfIterCount = pinDefaultKdfIterCount
	}

	if err := store.GeneratePassphrase(pin, pepper, int(pinKdfIterCount)); err != nil {
		logger.WithError(err).Fatal("could not initialize store")
	}

	return store
}

func createEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	entry := &enpass.EntryData{
		Title:    *args.title,
		Username: *args.login,
		Password: *args.password,
		URL:      *args.url,
		Notes:    *args.notes,
		Category: *args.category,
	}

	// Prompt for required fields if not provided
	if entry.Title == "" {
		entry.Title = promptText(logger, args, "title")
		if entry.Title == "" {
			logger.Fatal("title is required")
		}
	}

	// Prompt for password if flag was not provided
	if *args.password == "" {
		entry.Password = prompt(logger, args, "password")
	}

	uuid, err := vault.CreateEntry(entry)
	if err != nil {
		logger.WithError(err).Fatal("could not create entry")
	}

	logger.Printf("Created entry: %s (UUID: %s)", entry.Title, uuid)
}

func editEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	card, err := vault.GetEntry(*args.cardType, args.filters, true)
	if err != nil {
		logger.WithError(err).Fatal("could not find unique entry to edit")
	}

	updates := &enpass.EntryData{
		Title:    *args.title,
		Username: *args.login,
		URL:      *args.url,
		Notes:    *args.notes,
		Category: *args.category,
	}

	// Handle password - prompt if flag was passed but empty
	if isFlagPassed("password") && *args.password == "" {
		updates.Password = prompt(logger, args, "new password")
	} else {
		updates.Password = *args.password
	}

	// Confirm if changing password
	if updates.Password != "" && !*args.force {
		if !confirm(logger, args, fmt.Sprintf("Update password for '%s'?", card.Title)) {
			logger.Info("cancelled")
			return
		}
	}

	if err := vault.UpdateEntry(card.UUID, updates); err != nil {
		logger.WithError(err).Fatal("could not update entry")
	}

	logger.Printf("Updated entry: %s", card.Title)
}

func trashEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	card, err := vault.GetEntry(*args.cardType, args.filters, true)
	if err != nil {
		logger.WithError(err).Fatal("could not find unique entry to trash")
	}

	if !*args.force {
		if !confirm(logger, args, fmt.Sprintf("Move '%s' to trash?", card.Title)) {
			logger.Info("cancelled")
			return
		}
	}

	if err := vault.TrashEntry(card.UUID); err != nil {
		logger.WithError(err).Fatal("could not trash entry")
	}

	logger.Printf("Moved to trash: %s", card.Title)
}

func restoreEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	// For restore, we need to look in trashed items
	vault.FilterAnd = *args.and
	cards, err := vault.GetEntries(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve entries")
	}

	// Find trashed entry matching filter
	var card *enpass.Card
	for _, c := range cards {
		if c.IsTrashed() && !c.IsDeleted() {
			if card != nil {
				logger.Fatal("multiple trashed entries match that filter")
			}
			card = &c
		}
	}

	if card == nil {
		logger.Fatal("no trashed entry found matching filter")
	}

	if !*args.force {
		if !confirm(logger, args, fmt.Sprintf("Restore '%s' from trash?", card.Title)) {
			logger.Info("cancelled")
			return
		}
	}

	if err := vault.RestoreEntry(card.UUID); err != nil {
		logger.WithError(err).Fatal("could not restore entry")
	}

	logger.Printf("Restored: %s", card.Title)
}

func deleteEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	// For delete, we need to look in trashed items
	vault.FilterAnd = *args.and
	cards, err := vault.GetEntries(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve entries")
	}

	// Find trashed entry matching filter
	var card *enpass.Card
	for _, c := range cards {
		if c.IsTrashed() && !c.IsDeleted() {
			if card != nil {
				logger.Fatal("multiple trashed entries match that filter")
			}
			card = &c
		}
	}

	if card == nil {
		if !*args.force {
			logger.Fatal("no trashed entry found - use 'trash' first or --force to delete directly")
		}
		// With --force, allow deleting non-trashed entries
		entry, err := vault.GetEntry(*args.cardType, args.filters, true)
		if err != nil {
			logger.WithError(err).Fatal("could not find entry to delete")
		}
		card = entry
	}

	if !*args.force {
		if !confirm(logger, args, fmt.Sprintf("PERMANENTLY delete '%s'? This cannot be undone!", card.Title)) {
			logger.Info("cancelled")
			return
		}
	}

	if err := vault.DeleteEntry(card.UUID); err != nil {
		logger.WithError(err).Fatal("could not delete entry")
	}

	logger.Printf("Permanently deleted: %s", card.Title)
}

func promptText(logger *logrus.Logger, args *Args, msg string) string {
	if *args.nonInteractive {
		return ""
	}
	fmt.Printf("Enter %s: ", msg)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	return strings.TrimSpace(response)
}

func confirm(logger *logrus.Logger, args *Args, msg string) bool {
	if *args.nonInteractive {
		return false
	}
	fmt.Printf("%s [y/N]: ", msg)
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(response) == "y" || strings.ToLower(response) == "yes"
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func main() {
	args := &Args{}
	args.parse()

	logLevel, err := logrus.ParseLevel(*args.logLevelStr)
	if err != nil {
		logrus.WithError(err).Fatal("invalid log level specified")
	}
	logger := logrus.New()
	logger.SetLevel(logLevel)

	if _, contains := commands[args.command]; !contains {
		printHelp()
		logger.Exit(1)
	}

	switch args.command {
	case cmdHelp:
		printHelp()
		return
	case cmdVersion:
		logger.Printf(
			"%s arch=%s os=%s version=%s",
			filepath.Base(os.Args[0]), runtime.GOARCH, runtime.GOOS, version,
		)
		return
	}

	vault, err := enpass.NewVault(*args.vaultPath, logger.Level)
	if err != nil {
		logger.WithError(err).Fatal("could not create vault")
	}
	vault.FilterAnd = *args.and

	var store *unlock.SecureStore
	if !*args.pinEnable {
		logger.Debug("PIN disabled")
	} else {
		logger.Debug("PIN enabled, using store")
		store = initializeStore(logger, args)
		logger.Debug("initialized store")
	}

	credentials := assembleVaultCredentials(logger, args, store)

	defer func() {
		vault.Close()
	}()
	if err := vault.Open(credentials); err != nil {
		logger.WithError(err).Error("could not open vault")
		logger.Exit(2)
	}
	logger.Debug("opened vault")

	switch args.command {
	case cmdDryRun:
		logger.Debug("dry run complete") // just init vault and store without doing anything
	case cmdList:
		listEntries(logger, vault, args)
	case cmdShow:
		showEntries(logger, vault, args)
	case cmdCopy:
		copyEntry(logger, vault, args)
	case cmdPass:
		entryPassword(logger, vault, args)
	case cmdUi:
		ui(logger, vault, args)
	case cmdCreate:
		createEntry(logger, vault, args)
	case cmdEdit:
		editEntry(logger, vault, args)
	case cmdTrash:
		trashEntry(logger, vault, args)
	case cmdRestore:
		restoreEntry(logger, vault, args)
	case cmdEnv:
		envEntries(logger, vault, args)
	case cmdDelete:
		deleteEntry(logger, vault, args)
	default:
		logger.WithField("command", args.command).Fatal("unknown command")
	}

	if store != nil {
		if err := store.Write(credentials.DBKey); err != nil {
			logger.WithError(err).Fatal("failed to write credentials to store")
		}
	}
}
