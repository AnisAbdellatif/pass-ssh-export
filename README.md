# pass-ssh-export

Use the [Proton Pass](https://proton.me/pass) SSH agent without hand-copying public keys.

`pass-ssh-export` writes the **public** key of every SSH key item in your Proton Pass vaults to
`~/.ssh/<name>.pub`, so you can point `IdentityFile` at it while the private keys stay in Proton
Pass and signing is done by its SSH agent. It can also pull a shared ssh config from a Proton Pass
note and wire it into `~/.ssh/config`.

Private keys are never read: only the `public_key` field is fetched.

Works on macOS, Linux and Windows. Pure Python 3.9+ standard library.

## Requirements

- [`pass-cli`](https://proton.me/pass/download) in `PATH`, logged in (`pass-cli login`)
- Python 3.9+

## Install

```sh
pipx install git+https://github.com/AnisAbdellatif/pass-ssh-export
# or: pip install --user git+https://github.com/AnisAbdellatif/pass-ssh-export
```

## Usage

```
pass-ssh-export [-d DIR] [-c TITLE] [-C] [-K] [-f] [-n]
  -d, --dir DIR           output directory (default: ~/.ssh)
  -c, --config-title T    title of the note holding the shared config (default: ssh-config)
  -C, --no-config         don't pull the config note
  -K, --no-keys           don't export the public keys (config note only)
  -f, --force             overwrite existing .pub files whose key differs
  -n, --dry-run           show what would be written
```

Typical flow: run `pass-ssh-export -n`, then `pass-ssh-export`, then in `~/.ssh/config`:

```
Host myserver
  IdentityFile ~/.ssh/ssh-myserver.pub
  IdentitiesOnly yes
```

File names are the item title slugified (`SSH: My Server` -> `ssh-my-server.pub`); duplicates get
`-2`, `-3`, ... The key comment is set to the item title so keys are recognisable in `ssh-add -L`.
The command is idempotent and never overwrites a different key without `--force`.

### Shared config note

If a note titled `ssh-config` exists (any vault), its content is written to
`<dir>/config.d/protonpass.conf` and a trailing `Match all` + `Include .../config.d/*.conf` is
appended to `<dir>/config` once. ssh uses the first value per option, so your local settings above
the Include win. Edit the note, not the generated file. Only store config you trust in that note:
ssh config can run commands (`ProxyCommand`, `LocalCommand`).

## Exit status

`0` success, `1` error or at least one item failed, `130` interrupted.

## Development

```sh
pip install -e . ruff
ruff check .
python -m unittest discover -s tests
```

## License

MIT
