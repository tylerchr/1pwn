# `1pwn`

A utility for searching a 1Password `.agilekeychain` database for pwned passwords, using the [Have I been pwned?](https://haveibeenpwned.com/) V2 [range API](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange).

I think [1Password]() is a phenomenal product, and [Finding Pwned Passwords With 1Password](https://blog.agilebits.com/2018/02/22/finding-pwned-passwords-with-1password/) is a good example of why. However, my usage of 1Password isn't with 1Password.com, but rather a local database synced via Dropbox. I didn't want to miss out on the fun.

Note: Only `.agilekeychain` databases are supported. A contribution to support OPVault would be welome.

## Disclaimer

Use at your own risk! Dealing with passwords is a sensitive matter.

This utility doesn't do anything malicious and by my investigation neither do any of its dependencies ([speakeasy](https://github.com/bgentry/speakeasy), [color](https://github.com/fatih/color), [1pass](https://github.com/robertknight/1pass)), but you should of course verify this for yourself before entrusting your 1Password database to my code.

## Usage

Usage should be self-explanatory: pass the path to `.agilekeychain` as the first argument.

```
$ go install github.com/tylerchr/1pwn
$ 1pwn
USAGE: 1pwn [-verbose] <path/to.agilekeychain>
```

### Example

When either your 1Password master password or another stored password is found to have been pwned, you'll see output like this:

```
$ 1pwn ~/Dropbox/Security/InsecureVault.agilekeychain
Master Password:
Compromised password found: P@ssword (1Password master password, leaked 5728 times)
Your 1Password master password has been pwned, and it protects all other data in 1Password.
Change your master password immediately!
Compromised password found: abc123 (Google, leaked 2670319 times)
```

### Scripting usage

The utility requires the 1Password Master Password to access individual passwords. Normally this is collected at runtime via a password prompt, but noninteractive users can set the `ONEPASSWORD_MASTER_PASSWORD` environment variable instead. If this variable is found and non-empty, its value will automatically be used as the master password.

All warnings about pwned passwords are written to stderr. Informative lines like those enabled by the `-verbose` flag are sent to stdout instead. This enables usage like

```
$ 1pwn ~/Dropbox/Security/InsecureVault.agilekeychain 1>/dev/null
```

to suppress all non-pwnage output.

Note that if you do pipe stdout to `/dev/null` but don't have `ONEPASSWORD_MASTER_PASSWORD` set, you won't see the password prompt but it'll still wait for input and you'll think the program is hanging forever.