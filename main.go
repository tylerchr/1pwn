package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tylerchr/1pwn/internal/hibp"

	"github.com/bgentry/speakeasy"
	"github.com/fatih/color"
	"github.com/robertknight/1pass/onepass"
)

func main() {

	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "show item names as they are scanned")
	flag.Parse()

	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("USAGE: %s [-verbose] <path/to.agilekeychain>\n", os.Args[0])
		os.Exit(1)
	}

	// validate that it's a real vault
	if err := onepass.CheckVault(args[0]); err != nil {
		fmt.Printf("not a valid 1Password vault: %s\n", err)
		os.Exit(1)
	}

	// attempt to open the fault
	v, err := onepass.OpenVault(args[0])
	if err != nil {
		fmt.Printf("failed to open vault: %s\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stdout, "Opened vault: %s\n", args[0])
	}

	// obtain the vault's master password
	//
	// We'll try first for the ONEPASSWORD_MASTER_PASSWORD environment variable
	// but if that doesn't exist we'll just fall back to asking the user for it.
	masterPassword := os.Getenv("ONEPASSWORD_MASTER_PASSWORD")
	if masterPassword == "" {
		if masterPassword, err = speakeasy.Ask("Master Password: "); err != nil {
			panic(err)
		}
	}

	if err := v.Unlock(masterPassword); err != nil {
		fmt.Printf("failed to unlock vault: %s\n", err)
		panic(err)
	}

	if verbose {
		fmt.Fprintf(os.Stdout, "Unlocked vault: %s\n", args[0])
	}

	var check hibp.Checker

	// scan the master password
	if freq := check.Pwned(masterPassword); freq > 0 {
		fmt.Fprintf(os.Stderr, "Compromised password found: %s (1Password master password, leaked %d times)\n", color.RedString(masterPassword), freq)
		fmt.Fprintf(os.Stderr, "%s\n", color.YellowString("Your 1Password master password has been pwned, and it protects all other data in 1Password."))
		fmt.Fprintf(os.Stderr, "%s\n", color.YellowString("Change your master password immediately!"))
	}

	// the real meat: scan all the passwords
	err = ScanOnePassword(v, func(item onepass.Item, pwds []string) bool {

		if verbose {
			fmt.Fprintln(os.Stdout, item.Title)
		}

		for _, pwd := range pwds {
			if freq := check.Pwned(pwd); freq > 0 {
				fmt.Fprintf(os.Stderr, "Compromised password found: %s (%s, leaked %d times)\n", color.RedString(pwd), item.Title, freq)
			}
		}

		return false
	})

	if err != nil {
		panic(err)
	}

}

// ScanOnePassword searches a 1Password vault for passwords and invokes a callback with
// a list of passwords found for each item.
//
// ScanOnePassword skips items in the Trash.
func ScanOnePassword(v onepass.Vault, cb func(item onepass.Item, passwords []string) bool) error {

	items, err := v.ListItems()
	if err != nil {
		return fmt.Errorf("failed to list items: %s\n", err)
	}

	for _, item := range items {

		// skip trashed items
		if item.Trashed {
			continue
		}

		var passwords []string

		switch item.TypeName {
		case "passwords.Password":
			// decrypt the item
			icj, err := item.ContentJson()
			if err != nil {
				return fmt.Errorf("failed to decrypt item: %s: %s\n", item.Title, err)
			}

			var passes struct {
				Password string `json:"Password"`
				URLs     []struct {
					URL      string `json:"url"`
					Password string `json:"password"`
				} `json:"URLs"`
			}

			if err := json.Unmarshal([]byte(icj), &passes); err != nil {
				return err
			}

			if passes.Password != "" {
				passwords = append(passwords, passes.Password)
			}

			for _, url := range passes.URLs {
				passwords = append(passwords, url.Password)
			}

		default:
			// decrypt the item
			ic, err := item.Content()
			if err != nil {
				return err
			}

			for _, field := range ic.FormFields {
				if field.Type == "P" {
					passwords = append(passwords, field.Value)
				}
			}

		}

		if stop := cb(item, passwords); stop {
			return nil
		}

	}

	return nil

}
