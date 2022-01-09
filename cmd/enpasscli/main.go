package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	s "sort"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/hazcod/enpass-cli/pkg/enpass"
	"github.com/miquella/ask"
	"github.com/sirupsen/logrus"
)

const (
	defaultLogLevel = logrus.InfoLevel
)

var (
	// overwritten by go build
	version = "dev"
	// enables prompts
	interactive = true
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

func main() {
	vaultPath := flag.String("vault", "", "Path to your Enpass vault.")
	cardType := flag.String("type", "password", "The type of your card. (password, ...)")
	keyFilePath := flag.String("keyfile", "", "Path to your Enpass vault keyfile.")
	logLevelStr := flag.String("log", defaultLogLevel.String(), "The log level from debug (5) to error (1).")
	nonInteractive := flag.Bool("nonInteractive", false, "Disable prompts and fail instead.")
	sort := flag.Bool("sort", false, "Sort the output by title and username of the 'list' and 'show' command.")
	trashed := flag.Bool("trashed", false, "Show trashed items in the 'list' and 'show' command.")
	clipboardPrimary := flag.Bool("clipboardPrimary", false, "Use primary X selection instead of clipboard for the 'copy' command.")

	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Println("Specify a command: version, list, show, copy, pass")
		flag.Usage()
		os.Exit(1)
	}

	logLevel, err := logrus.ParseLevel(*logLevelStr)
	if err != nil {
		logrus.WithError(err).Fatal("invalid log level specified")
	}
	logger := logrus.New()
	logger.SetLevel(logLevel)

	command := strings.ToLower(flag.Arg(0))
	filters := flag.Args()[1:]

	interactive = !*nonInteractive

	if *clipboardPrimary {
		clipboard.Primary = true
		logger.Debug("primary X selection enabled")
	}

	if command == "version" {
		logger.Printf(
			"%s arch=%s os=%s version=%s",
			filepath.Base(os.Args[0]), runtime.GOARCH, runtime.GOOS, version,
		)
		return
	}

	masterPassword := os.Getenv("MASTERPW")
	if masterPassword == "" {
		masterPassword = prompt(logger, "master password")
	}

	if masterPassword == "" {
		logger.Fatal("no master password provided. (via cli or MASTERPW env variable)")
	}

	vault := enpass.Vault{Logger: *logrus.New()}
	vault.Logger.SetLevel(logger.Level)

	if err := vault.Initialize(*vaultPath, *keyFilePath, masterPassword); err != nil {
		logger.WithError(err).Error("could not open vault")
		logger.Exit(2)
	}
	defer func() { _ = vault.Close() }()

	logger.Debug("initialized vault")

	switch command {
	case "list":
		listEntries(logger, &vault, *cardType, *sort, *trashed, filters)
	case "show":
		showEntries(logger, &vault, *cardType, *sort, *trashed, filters)
	case "copy":
		copyEntry(logger, &vault, *cardType, filters)
	case "pass":
		entryPassword(logger, &vault, *cardType, filters)
	default:
		logger.WithField("command", command).Fatal("unknown command")
	}
}
