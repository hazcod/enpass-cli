package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	s "sort"
	"strings"

	"github.com/hazcod/enpass-cli/pkg/clipboard"
	"github.com/hazcod/enpass-cli/pkg/enpass"
	"github.com/hazcod/enpass-cli/pkg/pin"
	"github.com/miquella/ask"
	"github.com/sirupsen/logrus"
)

const (
	defaultLogLevel = logrus.InfoLevel
	cmdVersion      = "version"
	cmdHelp         = "help"
	cmdInit         = "init"
	cmdList         = "list"
	cmdShow         = "show"
	cmdCopy         = "copy"
	cmdPass         = "pass"
)

var (
	// overwritten by go build
	version = "dev"
	// enables prompts
	interactive = true
	commands    = map[string]struct{}{cmdVersion: {}, cmdHelp: {}, cmdInit: {}, cmdList: {}, cmdShow: {}, cmdCopy: {}, cmdPass: {}}
)

func prompt(logger *logrus.Logger, msg string) string {
	if interactive {
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
	s.SliceStable(cards, func(i, j int) bool {
		return strings.ToLower(cards[i].Subtitle) < strings.ToLower(cards[j].Subtitle)
	})
	// Sort by title, preserving username order
	s.SliceStable(cards, func(i, j int) bool {
		return strings.ToLower(cards[i].Title) < strings.ToLower(cards[j].Title)
	})
}

func listEntries(logger *logrus.Logger, vault *enpass.Vault, cardType string, sort bool, trashed bool, filters []string) {
	cards, err := vault.GetEntries(cardType, filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve cards")
	}
	if sort {
		sortEntries(cards)
	}
	for _, card := range cards {
		if card.IsTrashed() && !trashed {
			continue
		}
		logger.Printf(
			"> title: %s"+
				"  login: %s"+
				"  cat. : %s",
			card.Title,
			card.Subtitle,
			card.Category,
		)
	}
}

func showEntries(logger *logrus.Logger, vault *enpass.Vault, cardType string, sort bool, trashed bool, filters []string) {
	cards, err := vault.GetEntries(cardType, filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve cards")
	}
	if sort {
		sortEntries(cards)
	}
	for _, card := range cards {
		if card.IsTrashed() && !trashed {
			continue
		}
		password, err := card.Decrypt()
		if err != nil {
			logger.WithError(err).Error("could not decrypt " + card.Title)
			continue
		}

		logger.Printf(
			"> title: %s"+
				"  login: %s"+
				"  cat. : %s"+
				"  pass : %s",
			card.Title,
			card.Subtitle,
			card.Category,
			password,
		)
	}
}

func copyEntry(logger *logrus.Logger, vault *enpass.Vault, cardType string, filters []string) {
	card, err := vault.GetUniqueEntry(cardType, filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve unique card")
	}

	password, err := card.Decrypt()
	if err != nil {
		logger.WithError(err).Fatal("could not decrypt card")
	}

	if err := clipboard.WriteAll(password); err != nil {
		logger.WithError(err).Fatal("could not copy password to clipboard")
	}
}

func entryPassword(logger *logrus.Logger, vault *enpass.Vault, cardType string, filters []string) {
	card, err := vault.GetUniqueEntry(cardType, filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve unique card")
	}

	if password, err := card.Decrypt(); err != nil {
		logger.WithError(err).Fatal("could not decrypt card")
	} else {
		fmt.Println(password)
	}
}

func getVaultAccessData(logger *logrus.Logger, vaultPath string, enablePin bool) (*enpass.VaultAccessData, *pin.SecureStore) {
	accessData := &enpass.VaultAccessData{
		Password: os.Getenv("MASTERPW"),
	}

	var store *pin.SecureStore
	if !enablePin {
		logger.Debug("PIN disabled")
	} else if !accessData.IsComplete() {
		logger.Debug("PIN enabled, using store")

		storePin := os.Getenv("PIN")
		if storePin == "" {
			storePin = prompt(logger, "PIN")
		}

		var err error
		store, err = pin.NewSecureStore(filepath.Base(vaultPath), storePin, logger.Level)
		if err != nil {
			logger.WithError(err).Fatal("could not initialize store")
		}
		logger.Debug("initialized store")

		if accessData.DBKey, err = store.Read(); err != nil {
			logger.WithError(err).Fatal("could not read access data from store")
		}
		logger.Debug("read access data from store")
	}

	if !accessData.IsComplete() {
		accessData.Password = prompt(logger, "master password")
	}

	return accessData, store
}

func main() {
	vaultPath := flag.String("vault", "", "Path to your Enpass vault.")
	cardType := flag.String("type", "password", "The type of your card. (password, ...)")
	keyFilePath := flag.String("keyfile", "", "Path to your Enpass vault keyfile.")
	logLevelStr := flag.String("log", defaultLogLevel.String(), "The log level from debug (5) to error (1).")
	nonInteractive := flag.Bool("nonInteractive", false, "Disable prompts and fail instead.")
	enablePin := flag.Bool("pin", false, "Enable PIN.")
	sort := flag.Bool("sort", false, "Sort the output by title and username of the 'list' and 'show' command.")
	trashed := flag.Bool("trashed", false, "Show trashed items in the 'list' and 'show' command.")
	clipboardPrimary := flag.Bool("clipboardPrimary", false, "Use primary X selection instead of clipboard for the 'copy' command.")

	flag.Parse()

	logLevel, err := logrus.ParseLevel(*logLevelStr)
	if err != nil {
		logrus.WithError(err).Fatal("invalid log level specified")
	}
	logger := logrus.New()
	logger.SetLevel(logLevel)

	cmd := strings.ToLower(flag.Arg(0))
	filters := flag.Args()[1:]

	if _, contains := commands[cmd]; !contains {
		printHelp()
		logger.Exit(1)
	}

	switch cmd {
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

	interactive = !*nonInteractive

	if *clipboardPrimary {
		clipboard.Primary = true
		logger.Debug("primary X selection enabled")
	}

	vault, err := enpass.NewVault(*vaultPath, logger.Level)
	if err != nil {
		logger.WithError(err).Fatal("could not create vault")
	}

	accessData, store := getVaultAccessData(logger, *vaultPath, *enablePin)
	accessData.KeyfilePath = *keyFilePath

	if err := vault.Open(accessData); err != nil {
		logger.WithError(err).Error("could not open vault")
		logger.Exit(2)
	}
	logger.Debug("opened vault")
	defer func() {
		vault.Close()
		logger.Debug("closed vault")
	}()

	switch cmd {
	case cmdInit:
		// just init vault and store without doing anything
	case cmdList:
		listEntries(logger, vault, *cardType, *sort, *trashed, filters)
	case cmdShow:
		showEntries(logger, vault, *cardType, *sort, *trashed, filters)
	case cmdCopy:
		copyEntry(logger, vault, *cardType, filters)
	case cmdPass:
		entryPassword(logger, vault, *cardType, filters)
	default:
		logger.WithField("command", cmd).Fatal("unknown command")
	}

	if store != nil {
		if err := store.Write(accessData.DBKey); err != nil {
			logger.WithError(err).Fatal("failed to write access data to store")
		}
	}
}
