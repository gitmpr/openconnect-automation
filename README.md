# vpn-automation

Noninteractive VPN connection using [OpenConnect](https://www.infradead.org/openconnect/) with MFA (AD password + TOTP).

Invoked via a shell alias — no manual input required once configured.

```bash
alias vpn='python3 /path/to/vpn-automation/openconnect_pexpect.py'
```

## How it works

The script uses [pexpect](https://pexpect.readthedocs.io/) to drive `openconnect` noninteractively. The protocol (Juniper NetConnect `nc`, Pulse Secure `pulse`, etc.) is set in `config/vpn.conf`. During the authentication handshake it:

1. Reads all settings from `config/vpn.conf`
2. Retrieves the AD password (from a secret store or plain text in config)
3. Generates a TOTP code (from a secret store or plain text secret in config)
4. Feeds both to `openconnect` as it prompts for them
5. Configures split DNS via `systemd-resolved` once the `tun0` interface is up
6. Hands the process back to the terminal for the duration of the session
7. Cleans up DNS configuration on disconnect (Ctrl+C)

If a session limit is reached, the script automatically selects and kills the oldest active session. If an `openconnect` process is already running it exits immediately rather than triggering a server-side session eviction.

## Dependencies

```bash
sudo apt install openconnect oathtool libsecret-tools python3-pexpect
# or via pip if python3-pexpect is not available as a system package:
pip install pexpect
```

## Setup

### 1. Clone and configure

```bash
git clone https://github.com/gitmpr/vpn-automation
cd vpn-automation
cp config/vpn.conf.EXAMPLE config/vpn.conf
```

Edit `config/vpn.conf` and fill in:
- Your VPN portal URL and username
- Your DNS servers and search domains
- Your credential retrieval method (see below)

### 2. Obtaining the TOTP base32 secret

The TOTP base32 secret is the seed that TOTP apps use to generate time-based codes. You need to extract it once and store it somewhere the script can read it. How to get it depends on where your TOTP credential currently lives.

**From an authenticator app that supports export (e.g. Aegis, andOTP, Raivo)**

These apps can export accounts to a JSON or plain-text file that includes the base32 secret directly. Look for an "Export" or "Backup" option in the app settings. The secret will appear as a string of uppercase letters and digits.

**From a QR code shown during initial enrollment**

If you still have access to the QR code that was shown when the TOTP account was first set up, scan it with any QR reader. The decoded value is an `otpauth://` URI containing the base32 secret in the `secret=` parameter:

```
otpauth://totp/Example:jdoe?secret=YOUR_BASE32_SECRET&issuer=Example
```

**From a Google Authenticator transfer QR code**

Google Authenticator's "Transfer accounts" export uses a proprietary protobuf encoding rather than a plain `otpauth://` URI. Use [extract_otp_secrets](https://github.com/scito/extract_otp_secrets) to decode it:

```bash
# Standalone binary — download from releases:
# https://github.com/scito/extract_otp_secrets/releases/latest
./extract_otp_secrets_linux_x86_64 transfer-export.png

# Or via Python:
python3 extract_otp_secrets.py transfer-export.png
```

**From a password manager**

If the TOTP secret was saved in a password manager (Bitwarden, KeePass, 1Password, etc.) alongside the account, retrieve it from there directly.

**Verifying the secret**

Once you have the base32 secret, confirm it generates valid codes before storing it:

```bash
oathtool --totp --base32 YOUR_BASE32_SECRET
```

Compare the output against what your authenticator app shows for the same account.

### 3. Credential retrieval

All credentials are configured in `config/vpn.conf` under `[credentials]`. Choose a backend for the AD password and for the TOTP secret — they can be different backends.

The `ad_password_cmd` and `totp_code_cmd` values are passed verbatim to `/bin/sh -c`, exactly as if typed in a terminal. Spaces, subshells `$(...)`, and pipes work as normal. No quoting of the config value itself is needed or supported — quoting only applies inside the command where an argument contains spaces (e.g. `bw get password "My Item"`).

#### secret-tool (GNOME Keyring / libsecret)

`secret-tool` stores secrets in the session keyring, unlocked automatically at login. Nothing sensitive lives in files.

Note: `secret-tool lookup` matches by attribute key-value pairs, not by label. The attributes used when storing must exactly match what is used when looking up.

```bash
# Store AD password (prompts interactively)
secret-tool store --label='VPN AD Password' service ad username jdoe@example.local

# Verify
secret-tool lookup service ad username jdoe@example.local

# Store TOTP base32 secret (prompts interactively)
secret-tool store --label='VPN TOTP' totp totp_vpn

# Verify
secret-tool lookup totp totp_vpn
```

In `config/vpn.conf`:

```ini
[credentials]
ad_username     = jdoe@example.local
ad_password_cmd = secret-tool lookup service ad username jdoe@example.local
totp_code_cmd   = oathtool --totp --base32 $(secret-tool lookup totp totp_vpn)
```

#### Bitwarden CLI

[Bitwarden CLI](https://bitwarden.com/help/cli/) works well if your credentials are already in Bitwarden. It requires an active session token exported once per login session:

```bash
export BW_SESSION=$(bw unlock --raw)

# Retrieve AD password by item name
bw get password "VPN AD Password"

# Retrieve TOTP code if the item has a TOTP seed configured in Bitwarden
bw get totp "VPN AD Password"

# Or retrieve a base32 secret stored as a custom field and pipe to oathtool
bw get item "VPN TOTP" | jq -r '.fields[] | select(.name=="secret") | .value' | xargs oathtool --totp --base32
```

In `config/vpn.conf`:

```ini
[credentials]
ad_username     = jdoe@example.local
ad_password_cmd = bw get password "VPN AD Password"
totp_code_cmd   = bw get totp "VPN AD Password"
```

Note: `BW_SESSION` must be set before running the `vpn` alias. Add the unlock call to your shell profile or a wrapper script.

#### KWallet (KDE)

```bash
# Store AD password
kwallet-query -w "VPN AD Password" -f vpn kdewallet

# Retrieve
kwallet-query -r "VPN AD Password" -f vpn kdewallet

# Store TOTP base32 secret
kwallet-query -w "VPN TOTP" -f vpn kdewallet

# Retrieve
kwallet-query -r "VPN TOTP" -f vpn kdewallet
```

In `config/vpn.conf`:

```ini
[credentials]
ad_username     = jdoe@example.local
ad_password_cmd = kwallet-query -r "VPN AD Password" -f vpn kdewallet
totp_code_cmd   = oathtool --totp --base32 $(kwallet-query -r "VPN TOTP" -f vpn kdewallet)
```

#### pass (GPG-based)

```bash
# Store AD password
pass insert vpn/ad-password

# Retrieve
pass show vpn/ad-password

# Store TOTP base32 secret
pass insert vpn/totp-secret

# Retrieve
pass show vpn/totp-secret
```

In `config/vpn.conf`:

```ini
[credentials]
ad_username     = jdoe@example.local
ad_password_cmd = pass show vpn/ad-password
totp_code_cmd   = oathtool --totp --base32 $(pass show vpn/totp-secret)
```

#### Plain text in config

Simplest to set up. Restrict file permissions to keep the secret off-limits to other users.

```bash
chmod 600 config/vpn.conf
```

```ini
[credentials]
ad_username = jdoe@example.local
ad_password = your_ad_password
totp_secret = YOUR_BASE32_SECRET
```

When `totp_secret` is set the script calls `oathtool` internally — you never need to manually compute a code.

### 4. Passwordless sudo for openconnect

OpenConnect must run as root. Add a sudoers drop-in so the script can invoke it without a password prompt:

```
# /etc/sudoers.d/openconnect
yourusername ALL=(ALL) NOPASSWD: /usr/sbin/openconnect
```

Create with:

```bash
sudo visudo -f /etc/sudoers.d/openconnect
```

### 5. Shell alias

Add to `~/.bashrc` or `~/.zshrc`:

```bash
alias vpn='python3 /path/to/vpn-automation/openconnect_pexpect.py'
```

## Usage

```bash
vpn      # connect — no prompts
Ctrl+C   # disconnect and restore DNS
```

## Configuration reference

`config/vpn.conf` is the single source of truth for all environment-specific settings.

**`[vpn]`**

| Key | Required | Description |
|---|---|---|
| `server` | yes | Full VPN portal URL |
| `username` | yes | VPN login username (no domain suffix) |
| `openconnect_path` | yes | Path to the openconnect binary |
| `protocol` | yes | `nc` (Juniper NetConnect), `pulse` (Pulse Secure), etc. |

**`[credentials]`**

| Key | Required | Description |
|---|---|---|
| `ad_username` | yes | AD username including domain suffix |
| `ad_password` | one of (A) | AD password as plain text |
| `ad_password_cmd` | one of (A) | Shell command that prints the AD password to stdout |
| `totp_secret` | one of (B) | Base32 TOTP secret — oathtool generates the code |
| `totp_code_cmd` | one of (B) | Shell command that prints the current TOTP code to stdout |

Exactly one key from group (A) and exactly one from group (B) must be set.

**`[dns_servers]`**

| Key | Required | Description |
|---|---|---|
| `primary` | yes | Primary VPN DNS server IP |
| `secondary` | yes | Secondary VPN DNS server IP |

**`[search_domains]`**

| Key | Required | Description |
|---|---|---|
| `domains` | no | Comma-separated corporate domains appended as DNS search suffixes on the VPN interface |

**`[routing_domains]`**

| Key | Required | Description |
|---|---|---|
| `domains` | no | Comma-separated domains forwarded to the VPN DNS server via systemd-resolved routing rules — usually the same list as `search_domains` |

## Files

| File | Purpose |
|---|---|
| `openconnect_pexpect.py` | Main connection script |
| `config/vpn.conf.EXAMPLE` | Config template — copy to `vpn.conf` and fill in |

`config/vpn.conf` (your filled-in copy) is gitignored and never committed.

## Security notes

- `config/vpn.conf` is gitignored — your credentials stay local
- If you store a plain-text password in the config, run `chmod 600 config/vpn.conf`
- The keyring approach keeps secrets off disk entirely
- The sudoers rule should be scoped to `/usr/sbin/openconnect` only
