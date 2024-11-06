package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

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
	and              *bool
	clipboardPrimary *bool
}

func (args *Args) parse() {
	args.vaultPath = flag.String("vault", "", "Path to your Enpass vault.")
	args.cardType = flag.String("type", "password", "The type of your card. (password, ...)")
	args.keyFilePath = flag.String("keyfile", "", "Path to your Enpass vault keyfile.")
	args.logLevelStr = flag.String("log", defaultLogLevel.String(), "The log level from debug (5) to error (1).")
	args.jsonOutput = flag.Bool("json", false, "Output data in JSON format.")
	args.nonInteractive = flag.Bool("nonInteractive", false, "Disable prompts and fail instead.")
	args.pinEnable = flag.Bool("pin", false, "Enable PIN.")
	args.and = flag.Bool("and", false, "Combines filters with AND instead of default OR.")
	args.sort = flag.Bool("sort", false, "Sort the output by title and username of the 'list' and 'show' command.")
	args.trashed = flag.Bool("trashed", false, "Show trashed items in the 'list' and 'show' command.")
	args.clipboardPrimary = flag.Bool("clipboardPrimary", false, "Use primary X selection instead of clipboard for the 'copy' command.")
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
	fmt.Print("Valid commands: ")
	for cmd := range commands {
		fmt.Printf("%s, ", cmd)
	}
	fmt.Println()
	flag.Usage()
	os.Exit(1)
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
	cards, err := vault.GetEntries(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve cards")
	}
	if *args.sort {
		sortEntries(cards)
	}

	data, err := prepareCardData(cards, false, args)
	if err != nil {
		logger.WithError(err).Fatal(err.Error())
	}

	outputDataOrLog(logger, data, args)
}

func showEntries(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	cards, err := vault.GetEntries(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve cards")
	}
	if *args.sort {
		sortEntries(cards)
	}

	data, err := prepareCardData(cards, true, args)
	if err != nil {
		logger.WithError(err).Fatal(err.Error())
	}

	outputDataOrLog(logger, data, args)
}

func prepareCardData(cards []enpass.Card, includeDecrypted bool, args *Args) ([]map[string]string, error) {
	data := make([]map[string]string, 0)
	for _, card := range cards {
		if card.IsTrashed() && !*args.trashed {
			continue
		}

		cardMap := map[string]string{
			"title":    card.Title,
			"login":    card.Subtitle,
			"category": card.Category,
			"label":    card.Label,
			"type":     card.Type,
		}

		if includeDecrypted {
			decrypted, err := card.Decrypt()
			if err != nil {
				return nil, fmt.Errorf("could not decrypt %s: %w", card.Title, err)
			}
			cardMap["password"] = decrypted
		}

		data = append(data, cardMap)
	}
	return data, nil
}

func outputDataOrLog(logger *logrus.Logger, data []map[string]string, args *Args) {
	if *args.jsonOutput {
		jsonData, jsonErr := json.Marshal(data)
		if jsonErr != nil {
			logger.WithError(jsonErr).Fatal("could not marshal JSON data")
		}
		fmt.Println(string(jsonData))
	} else {
		for _, card := range data {
			logger.Printf(
				"> title: %s  login: %s  cat.: %s  label: %s",
				card["title"],
				card["login"],
				card["category"],
				card["label"],
			)
		}
	}
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
	default:
		logger.WithField("command", args.command).Fatal("unknown command")
	}

	if store != nil {
		if err := store.Write(credentials.DBKey); err != nil {
			logger.WithError(err).Fatal("failed to write credentials to store")
		}
	}
}
