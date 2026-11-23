# kpx-share

Give an AI coding agent one KeePassXC entry for one session, as files in RAM that are deleted
when the session ends, and let it hand secrets it creates back into the database.

```
! kpx-share add github
/run/user/1000/kpx-share/claude-0b1c…/GitHub_token
```

You pick the entry. The agent gets a path, uses the files in it by path, and never needs to see
the value.

## Why

An agent working on real infrastructure soon needs a credential: an API token, a device password,
a TLS key. The usual ways to give it one are all poor:

- **Paste it into the chat.** It is now in a transcript that outlives the session and gets logged,
  summarised and shared.
- **Put it in a `.env` or config file.** That is a lasting plaintext copy, one `git add .` away
  from a commit.
- **Let the agent open the password manager.** It can now reach every secret you have, not the one
  the task needs.

kpx-share is the narrow path between these. You decide, per session, which entry the agent gets.
The entry lives on tmpfs only, and is gone when the agent's process exits or after 8 hours. The
same goes the other way: a key or certificate the agent generates is staged in RAM and added to the
database once you confirm, never left in `~` or a repo.

## What it is not

**It is not a sandbox.** The agent runs as you, so it can read anything you can, the database file
included. kpx-share does nothing to stop an agent that is trying to misbehave. What it does is make
the careful path the easy one for an agent that follows its instructions, and keep everyday mistakes
small: a secret that is never on disk can't be committed, and one that is gone at session end can't
be found by next week's session.

Each layer decides one thing:

| Layer | Decides |
|---|---|
| The KeePassXC tag `agent` | which entries may ever be shared |
| `! kpx-share add`, typed by you | which one is shared now |
| The session directory on tmpfs | how long it exists: until the agent's process exits or the TTL passes |
| Your instructions to the agent | that it uses the files without printing them; kpx-share cannot enforce this |
| `! kpx-share import`, typed by you, and its confirmation | what is added to the database: only added, never changed |

## Try it

Status: a personal tool, built for and used on one Arch Linux machine with Claude Code. Linux only. Paths
to the tools it runs are fixed (see below), so other distributions may need edits.

You need KeePassXC 2.8 (`keepassxc-cli`), a systemd user session, a Rust toolchain and
[`just`](https://github.com/casey/just), plus `fuzzel` and `pinentry-gnome3` for use from Claude
Code's `!` commands (which have no terminal), or `fzf` for use from a terminal.

1. Install: `just install` builds a release binary into `~/.cargo/bin/kpx-share`.
2. Point it at your database, for example in fish:

   ```fish
   set -gx KPX_SHARE_DB ~/path/to/vault.kdbx
   ```

3. In KeePassXC, add the tag `agent` to an entry an agent may have.
4. Tell the agent how to use a share. A minimal instruction for `CLAUDE.md`:

   > A secret I share with `kpx-share add` is a directory of files under
   > `$XDG_RUNTIME_DIR/kpx-share/`: `username`, `password`, `url`, `notes`, `otp`, `attributes/`,
   > `attachments/` and a `meta.json` that maps field names to files. Use them by path, on stdin,
   > or as `$(cat …)` inside a command. Never print one, copy it elsewhere, or run
   > `kpx-share add` yourself; ask me to run it.

5. In Claude Code, run `! kpx-share add <word from the entry's title>`. You unlock the database,
   and the agent sees the printed path. `! kpx-share rm --all` removes it before it expires.

## How it works

- **Unlock.** `keepassxc-cli export` decrypts the database into kpx-share's memory, with the
  password from pinentry (or a terminal prompt, or gpg, below). The process is non-dumpable and
  makes no core files, and decrypted data is wiped when it is dropped.
- **Pick.** Entries without the tag are dropped. Each word of the query must match an entry's
  `Group/Title`, username or URL; one match is taken, several open a picker.
- **Write.** The entry is written as files, mode `0600`, into a per-session directory under
  `$XDG_RUNTIME_DIR/kpx-share/`. kpx-share checks the directory is on tmpfs before it unlocks
  anything. The session is the Claude Code session (`CLAUDE_CODE_SESSION_ID`, `CLAUDE_PID`), or
  the parent shell outside Claude Code.
- **Clean up.** Before the first file is written, a `systemd-run --user` watcher starts. It
  deletes the session directory when the watched process exits or the TTL passes.
- **Import.** The agent stages files plus a `manifest.json` in `$XDG_RUNTIME_DIR/kpx-import/<name>/`.
  `kpx-share import <name>` shows you a summary (names and sizes, no values), adds the entry or
  attachments to a copy of the database with `keepassxc-cli`, checks the copy holds every staged
  byte and that nothing else in it changed, then replaces the database with one rename and deletes
  the staged files.

kpx-share never reads or writes the KDBX format itself: `keepassxc-cli` does every unlock and every
write of the database.

## Configure

| Option | Variable | Meaning |
|---|---|---|
| `--db PATH` | `KPX_SHARE_DB` | the `.kdbx` file (required) |
| `--key-file PATH` | `KPX_SHARE_KEY_FILE` | its key file |
| `--password-gpg PATH` | `KPX_SHARE_PASSWORD_GPG` | the master password, OpenPGP-encrypted; decrypted with gpg instead of asking |
| `--no-password` | (flag only) | the database has a key file and no password |
| `--yubikey 1\|2` | `KPX_SHARE_YUBIKEY` | the database also needs this YubiKey challenge-response slot |
| `--tag TAG` | | the tag an entry must carry (default `agent`, case-insensitive) |
| `--any` | | any entry, tagged or not |
| `--ttl DURATION` | | how long the session lasts at most (default `8h`, at most a week) |

The tools it runs are found by absolute path, not `PATH`: `/usr/bin/keepassxc-cli`,
`/usr/bin/systemd-run`, `/usr/bin/systemctl`, `/usr/bin/fuzzel`, `/usr/bin/pinentry-gnome3`,
`/usr/bin/fzf`, and `/usr/bin/gpg` for `--password-gpg`. That way a stray `PATH` entry in the
agent's environment can't stand in for one of them.

### The password from a YubiKey (`--password-gpg`)

Instead of typing the master password, you can keep it encrypted to an OpenPGP key on a YubiKey.
Every `add` then takes one touch, attachments included, since the password is decrypted once and
held for the run. The database itself is unchanged, so the password and key file still open it if
the card is lost.

1. Turn touch on for decryption only (signing and ssh are unaffected): `gpg-card`, then
   `uif 2 on`. Check `gpg --card-status` shows `Decrypt=on`.
2. Encrypt the password to the card's encryption subkey, from a real terminal:

   ```fish
   mkdir -p ~/.config/kpx-share; chmod 700 ~/.config/kpx-share
   read -s -P 'KeePass password: ' pw; and printf %s $pw | gpg --encrypt -r '<subkey-id>!' -o ~/.config/kpx-share/password.gpg; set -e pw
   chmod 600 ~/.config/kpx-share/password.gpg
   ```

   The `!` makes gpg use exactly that subkey. Without it gpg picks the newest encryption subkey,
   which may not be the one on the card. Check with `gpg --list-only --list-packets <file>`,
   which shows the recipient's key id without decrypting.
3. Set `KPX_SHARE_PASSWORD_GPG` to that file. Keep it out of synced folders.

One trailing line feed in the decrypted text is not part of the password, so `echo pw | gpg -e`
works too. More than 4096 bytes is refused as the wrong file.

## Use

| Command | Does |
|---|---|
| `kpx-share add [query]` | unlock, pick one entry, write it into this session, print its directory |
| `kpx-share ls` | the entries shared into this session, with the session's expiry |
| `kpx-share rm <entry>` / `rm --all` | remove now |
| `kpx-share gc` | remove session directories whose session is gone or whose TTL passed |
| `kpx-share import <name>` | after you confirm, add what an agent staged in `$XDG_RUNTIME_DIR/kpx-import/<name>/` to the database |

Inside Claude Code, run them as `! kpx-share add …`. Don't let the agent run `add` or `import`
itself: your typing the command is the decision.

Adding an entry again replaces it in place. A session's expiry is set by its first `add` and is
never pushed back: a later `add` can only bring it forward with a shorter `--ttl`.

### What an entry looks like

```
<entry>/
  username  password  url  notes  title   always present; an empty file is an empty field
  otp                                    otpauth:// URI, if the entry has TOTP (any of its 3 formats)
  attributes/<name>                      custom fields
  attachments/<name>                     attachments, byte for byte
  meta.json                              path, uuid, tags, exported_at, expires_at, name → file maps
```

Directories are `0700`, files `0600`. Values are byte-exact, with no newline added. A name that is
not a safe file name is stored under another one, so go through `meta.json`'s `fields` and
`attachments` maps. Placeholders kpx-share could not resolve are listed in `meta.json`'s
`unresolved`.

`add` prints only the entry's path and `import` only names and sizes. Errors name files, keys and
tools, never a value. For a KDBX 4 database, whose XML export carries no attachment bytes, each
attachment of the picked entry is fetched with `keepassxc-cli attachment-export`, using the same
password.

## Import, in detail

`import` is the one command that writes the database, and it only adds: a new entry, or new
attachments on an existing one (`device.pem` onto `Devices/thermostat`). It never changes or
replaces a field or an attachment, generates a secret, or sets tags or notes; tag the entry in
KeePassXC.

### What the agent stages

```
$XDG_RUNTIME_DIR/kpx-import/           0700, made by the agent, on tmpfs
  <name>/                              0700; <name> is letters, digits, '.', '-', '_'
    manifest.json
    <file> …                           exactly the files the manifest names, nothing else
```

```json
{"kind": "new", "entry": "Group/Title", "username": "u", "url": "https://…",
 "password": "<file>", "attachments": {"<name in KeePassXC>": "<file>"}}
{"kind": "existing", "entry": "Group/Title", "attachments": {"<name in KeePassXC>": "<file>"}}
```

A new entry needs a password file, an attachment or both; `username` and `url` are optional and
empty when absent (leave them out rather than `""`). An existing entry gets at least one
attachment and nothing else. Each file is named once. Before you are asked anything, every rule
is checked and every file read once into memory: the directories are real directories of yours
with mode 0700 on tmpfs, each file a regular file of yours (no symlink); a password is 1 to 4096
bytes of UTF-8 without NUL, CR or LF (keepassxc-cli reads it as a line); an attachment is 1 byte
to 16 MiB, any bytes; names and plain fields have no control characters. The username and URL
reach keepassxc-cli as program arguments, which every user on the machine can read, so a URL
with credentials in its host part (`https://user:pass@host/`) is refused. The entry path is
matched the way keepassxc-cli finds it, so a path two entries share is refused.

### What happens

Don't save the database in KeePassXC while an import runs: the import then refuses, and you run
it again.

0. One import runs at a time: each holds a lock on `kpx-import/` for its whole run, and a second
   one refuses at once, touching nothing. The staging directory is then claimed: renamed to
   `kpx-import/.claimed.<random>.<name>`, out of the agent's way, and read from there. Every
   ending but a proven import renames it back. An import that is killed (Ctrl-C, a crash) leaves
   the directory renamed; the next import puts it back under its name first, and goes on, so
   running it again just works. If the name is taken by then, both are left as they are and
   reported; nothing claimed is ever deleted, since it may hold secrets in no database. Names
   in `kpx-import/` that are none of kpx-share's are left alone.
1. You confirm a summary: the database, the entry and whether it is new, its username and URL,
   and the size of the password and of each attachment (the first few listed, the rest counted,
   long values cut with `…`, so it fits a pinentry window). Under `!` that is a pinentry window;
   in a terminal it is printed and you answer `y`. Nothing is decrypted, and no password asked
   for, before you do. In a terminal the database password must come from `--password-gpg` (or a
   key file alone), since keepassxc-cli reads the entry's password from the same stdin.
2. The database file is resolved once (through symlinks; refused if it has a second hard link),
   read once, and copied into `kpx-import/.work-<random>/` (ciphertext, removed on every exit).
   What an interrupted import left of ours, all ciphertext, is removed first: `.work-*`
   directories, and `.<file>.kpx-import-*` copies beside the database.
3. The copy is unlocked and exported. Already holding everything staged, byte for byte (a rerun),
   skips to the cleanup; a staged attachment already there with other content, some of the
   staged attachments there but not all, an existing entry at a new entry's path, a new entry
   whose group does not exist outside the recycle bin (import makes no group: create it in
   KeePassXC), a missing one for `existing`, or one in the recycle bin, is refused.
4. keepassxc-cli writes the copy: `add` with the entry's password on stdin after the master
   password, `attachment-import` reading each attachment from a pipe (`/dev/fd/<n>`). No
   plaintext file is written.
5. The copy is exported again and compared with the first export: the target holds exactly what
   was staged, byte for byte; everything else about it, and every other entry (fields, attributes,
   TOTP, tags, attachment names, history), is unchanged; no entry is missing, and a new entry is
   the only one added. If KeePassXC dropped old history versions of the target to stay within the
   database's history limits, the import is refused, naming the setting to raise.
6. The proven copy is written beside the live file and synced; then, only if the live file still
   holds the bytes read in step 2 (nobody saved it meanwhile), the copy is renamed onto it at
   once, and the file is read back: it must be byte-identical to the proven copy, and so holds
   what was proven.
7. Each file that was read, and still holds what was read, is deleted, then the directory. A file
   that changed or appeared during the import is kept, the directory put back under its name,
   and reported.

stdout has one line per item (`added entry Group/T (password 32 bytes)`, `added attachment
device.pem (1234 bytes) to Group/T`, or `already in the database: …`); stderr reminds you to tag
the entry and to commit the `.kdbx` if you keep it in git. No value, or hash of one, is printed.

| Exit | Means |
|---|---|
| 0 | imported and proven, or already there; the staged files are deleted (even if stdout could not be written: stderr says so) |
| 1 | refused (another import running, too) or failed; the database is unchanged, the staged files kept |
| 3 | the database was replaced but is not proven to hold what was written: its directory could not be synced, or reading it back failed or gave other bytes; the staged files kept |
| 130 | you declined, or closed a dialog; nothing changed |

## Development

```
just check          # cargo fmt --check, clippy -D warnings, all tests
```

Tests use throwaway databases made with `keepassxc-cli`, fake pinentry and picker scripts, and a
throwaway gpg home with a software key, never your real database, keyring or card.

## License

MIT
