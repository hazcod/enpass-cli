package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/hazcod/enpass-cli/pkg/clipboard"
	"github.com/hazcod/enpass-cli/pkg/enpass"
	"github.com/hazcod/enpass-cli/pkg/pin"
	"github.com/miquella/ask"
	"github.com/sirupsen/logrus"
)

const (
	// commands
	cmdVersion = "version"
	cmdHelp    = "help"
	cmdInit    = "init"
	cmdList    = "list"
	cmdShow    = "show"
	cmdCopy    = "copy"
	cmdPass    = "pass"
	// defaults
	defaultLogLevel        = logrus.InfoLevel
	pinMinLength           = 8
	pinDefaultKdfIterCount = 100000
)

var (
	// overwritten by go build
	version = "dev"
	// set of all commands
	commands = map[string]struct{}{cmdVersion: {}, cmdHelp: {}, cmdInit: {}, cmdList: {},
		cmdShow: {}, cmdCopy: {}, cmdPass: {}}
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
	nonInteractive   *bool
	pinEnable        *bool
	sort             *bool
	trashed          *bool
	clipboardPrimary *bool
}

func (args *Args) parse() {
	args.vaultPath = flag.String("vault", "", "Path to your Enpass vault.")
	args.cardType = flag.String("type", "password", "The type of your card. (password, ...)")
	args.keyFilePath = flag.String("keyfile", "", "Path to your Enpass vault keyfile.")
	args.logLevelStr = flag.String("log", defaultLogLevel.String(), "The log level from debug (5) to error (1).")
	args.nonInteractive = flag.Bool("nonInteractive", false, "Disable prompts and fail instead.")
	args.pinEnable = flag.Bool("pin", false, "Enable PIN.")
	args.sort = flag.Bool("sort", false, "Sort the output by title and username of the 'list' and 'show' command.")
	args.trashed = flag.Bool("trashed", false, "Show trashed items in the 'list' and 'show' command.")
	args.clipboardPrimary = flag.Bool("clipboardPrimary", false, "Use primary X selection instead of clipboard for the 'copy' command.")
	flag.Parse()
	args.command = strings.ToLower(flag.Arg(0))
	args.filters = flag.Args()[1:]
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
	for _, card := range cards {
		if card.IsTrashed() && !*args.trashed {
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

func showEntries(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	cards, err := vault.GetEntries(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve cards")
	}
	if *args.sort {
		sortEntries(cards)
	}
	for _, card := range cards {
		if card.IsTrashed() && !*args.trashed {
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

func copyEntry(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	card, err := vault.GetUniqueEntry(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve unique card")
	}

	password, err := card.Decrypt()
	if err != nil {
		logger.WithError(err).Fatal("could not decrypt card")
	}

	if *args.clipboardPrimary {
		clipboard.Primary = true
		logger.Debug("primary X selection enabled")
	}

	if err := clipboard.WriteAll(password); err != nil {
		logger.WithError(err).Fatal("could not copy password to clipboard")
	}
}

func entryPassword(logger *logrus.Logger, vault *enpass.Vault, args *Args) {
	card, err := vault.GetUniqueEntry(*args.cardType, args.filters)
	if err != nil {
		logger.WithError(err).Fatal("could not retrieve unique card")
	}

	if password, err := card.Decrypt(); err != nil {
		logger.WithError(err).Fatal("could not decrypt card")
	} else {
		fmt.Println(password)
	}
}

func assembleVaultAccessData(logger *logrus.Logger, args *Args) (*enpass.VaultAccessData, *pin.SecureStore) {
	accessData := &enpass.VaultAccessData{
		Password: os.Getenv("MASTERPW"),
	}

	var store *pin.SecureStore
	if !*args.pinEnable {
		logger.Debug("PIN disabled")
	} else if !accessData.IsComplete() {
		logger.Debug("PIN enabled, using store")

		vaultPath, err := filepath.EvalSymlinks(*args.vaultPath)
		store, err = pin.NewSecureStore(filepath.Base(vaultPath), logger.Level)
		if err != nil {
			logger.WithError(err).Fatal("could not create store")
		}

		storePin := os.Getenv("ENP_PIN")
		if storePin == "" {
			storePin = prompt(logger, args, "PIN")
		}
		if len(storePin) < pinMinLength {
			logger.Fatal("PIN too short")
		}
		pinKdfIterCount, err := strconv.ParseInt(os.Getenv("ENP_PIN_ITER_COUNT"), 10, 64)
		if err != nil {
			pinKdfIterCount = pinDefaultKdfIterCount
		}
		if err := store.GeneratePassphrase(storePin, int(pinKdfIterCount)); err != nil {
			logger.WithError(err).Fatal("could not initialize store")
		}
		logger.Debug("initialized store")

		if accessData.DBKey, err = store.Read(); err != nil {
			logger.WithError(err).Fatal("could not read access data from store")
		}
		logger.Debug("read access data from store")
	}

	if !accessData.IsComplete() {
		accessData.Password = prompt(logger, args, "master password")
	}

	return accessData, store
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

	accessData, store := assembleVaultAccessData(logger, args)
	accessData.KeyfilePath = *args.keyFilePath

	defer func() {
		vault.Close()
	}()
	if err := vault.Open(accessData); err != nil {
		logger.WithError(err).Error("could not open vault")
		logger.Exit(2)
	}
	logger.Debug("opened vault")

	switch args.command {
	case cmdInit:
		logger.Debug("init done") // just init vault and store without doing anything
	case cmdList:
		listEntries(logger, vault, args)
	case cmdShow:
		showEntries(logger, vault, args)
	case cmdCopy:
		copyEntry(logger, vault, args)
	case cmdPass:
		entryPassword(logger, vault, args)
	default:
		logger.WithField("command", args.command).Fatal("unknown command")
	}

	if store != nil {
		if err := store.Write(accessData.DBKey); err != nil {
			logger.WithError(err).Fatal("failed to write access data to store")
		}
	}
}
