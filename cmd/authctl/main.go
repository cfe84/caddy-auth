package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cfe84/caddy-auth/internal/authsvc"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}
	dbPath := os.Getenv("CADDY_AUTH_DB")
	if dbPath == "" {
		dbPath = "caddy-auth.db"
	}
	store, err := authsvc.Open(dbPath)
	if err != nil {
		fatal(err)
	}
	defer store.Close()
	args := os.Args[1:]
	switch args[0] {
	case "credential":
		if len(args) == 3 && args[1] == "add" {
			password := readSecret("Password: ")
			if err := store.AddCredential(args[2], password); err != nil {
				fatal(err)
			}
		} else if len(args) == 3 && args[1] == "set-password" {
			password := readSecret("New password: ")
			if err := store.SetPassword(args[2], password); err != nil {
				fatal(err)
			}
		} else if len(args) == 3 && (args[1] == "enable" || args[1] == "disable") {
			if err := store.SetCredentialEnabled(args[2], args[1] == "enable"); err != nil {
				fatal(err)
			}
		} else {
			usage()
		}
	case "role":
		if len(args) != 3 || args[1] != "add" && args[1] != "remove" {
			usage()
		}
		var err error
		if args[1] == "add" {
			err = store.AddRole(args[2])
		} else {
			err = store.RemoveRole(args[2])
		}
		if err != nil {
			fatal(err)
		}
	case "membership":
		if len(args) != 4 || args[1] != "add" && args[1] != "remove" {
			usage()
		}
		var err error
		if args[1] == "add" {
			err = store.AssignRole(args[2], args[3])
		} else {
			err = store.RemoveMembership(args[2], args[3])
		}
		if err != nil {
			fatal(err)
		}
	case "site":
		if len(args) != 3 || args[1] != "add" {
			usage()
		}
		if err := store.RegisterSite(args[2]); err != nil {
			fatal(err)
		}
	default:
		usage()
	}
}

func readSecret(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	var value string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal(err)
		}
		value = string(secret)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && len(line) == 0 {
			fatal(err)
		}
		value = line
	}
	value = strings.TrimRight(value, "\r\n")
	if value == "" {
		fatal(fmt.Errorf("password cannot be empty"))
	}
	return value
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: authctl credential add|set-password|enable|disable NAME | role add|remove NAME | membership add|remove USER ROLE | site add HTTPS_ORIGIN")
	os.Exit(2)
}

func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
