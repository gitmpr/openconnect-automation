# vpn-automation

Noninteractive VPN connection using [OpenConnect](https://www.infradead.org/openconnect/) with MFA (AD password + TOTP).

Invoked via a shell alias — no manual input required once configured.

```bash
alias vpn='python3 /path/to/vpn-automation/openconnect_pexpect_nc.py'
```

## How it works

The script uses [pexpect](https://pexpect.readthedocs.io/) to drive `openconnect` in `--protocol=nc` (Juniper NetConnect) mode. During the authentication handshake it:

1. Reads all settings from `config/vpn.conf`
2. Retrieves the AD password (from keyring or plain text in config)
3. Generates a TOTP code (from keyring or plain text secret in config)
4. Feeds both to `openconnect` as it prompts for them
5. Configures split DNS via `systemd-resolved` once the `tun0` interface is up
6. Hands the process back to the terminal for the duration of the session
7. Cleans up DNS configuration on disconnect (Ctrl+C)

If a session limit is reached, the script automatically selects and kills the oldest active session.

## Dependencies

```bash
sudo apt install openconnect oathtool libsecret-tools python3-pexpect
# or via pip if python3-pexpect is not available as a system package:
pip install pexpect
```

## Setup

### 1. Clone and configure

```bash
git clone <repo-url> vpn-automation
cd vpn-automation
cp config/vpn.conf config/vpn.conf   # already present - edit it directly
```

Edit `config/vpn.conf` and fill in:
- Your VPN portal URL and username
- Your DNS servers and search domains
- Your credential retrieval method (see below)

### 2. Credential retrieval

All credentials are configured in `config/vpn.conf` under `[credentials]`.

Two methods are supported for the AD password and for the TOTP code. Choose one for each.

#### Option A: system keyring (recommended)

Credentials are stored in the GNOME Keyring / libsecret and retrieved at runtime via `secret-tool`. Nothing sensitive lives in files.

Store the AD password:

```bash
secret-tool store --label='VPN AD Password' service ad username jdoe@example.local
```

Store the TOTP base32 secret:

```bash
secret-tool store --label='VPN TOTP' totp totp_vpn
```

In `config/vpn.conf`, set:

```ini
[credentials]
ad_username     = jdoe@example.local
ad_password_cmd = secret-tool lookup service ad username jdoe@example.local
totp_code_cmd   = oathtool --totp --base32 $(secret-tool lookup totp totp_vpn)
```

`bash_commands/totp_command.sh` is a ready-made wrapper for the TOTP command above; you can reference it directly if you prefer:

```ini
totp_code_cmd = bash /path/to/vpn-automation/bash_commands/totp_command.sh
```

#### Option B: plain text in config

Simpler to set up, but requires restricting file permissions if the config contains your actual password.

```bash
chmod 600 config/vpn.conf
```

```ini
[credentials]
ad_username = jdoe@example.local
ad_password = your_ad_password
totp_secret = JBSWY3DPEHPK3PXP   # base32 TOTP secret; oathtool generates the code
```

Both methods can be mixed (e.g., plain username, command-retrieved password).

### 3. Obtaining the TOTP base32 secret

To extract the TOTP secret from a Google Authenticator export (QR code), use [extract_otp_secrets](https://github.com/scito/extract_otp_secrets):

```bash
# Export the account from Google Authenticator as a QR code, then:

# Using the standalone binary (no Python env needed):
./extract_otp_secrets_linux_x86_64 qr-export.png

# Or via Python:
python3 extract_otp_secrets.py qr-export.png
```

This outputs the base32 secret. Store it with `secret-tool` (Option A) or put it directly in the config (Option B).

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
alias vpn='python3 /path/to/vpn-automation/openconnect_pexpect_nc.py'
```

## Usage

```bash
vpn      # connect - no prompts
Ctrl+C   # disconnect and restore DNS
```

## Configuration reference

`config/vpn.conf` is the single source of truth for all environment-specific settings.

| Section | Key | Description |
|---|---|---|
| `[vpn]` | `server` | Full VPN portal URL |
| `[vpn]` | `username` | VPN login username (no domain) |
| `[vpn]` | `openconnect_path` | Path to openconnect binary |
| `[vpn]` | `protocol` | `nc` (NetConnect) or `pulse` (Pulse Secure) |
| `[credentials]` | `ad_username` | AD username including domain suffix |
| `[credentials]` | `ad_password` | AD password (plain text) |
| `[credentials]` | `ad_password_cmd` | Shell command that prints the AD password |
| `[credentials]` | `totp_secret` | Base32 TOTP secret (oathtool generates the code) |
| `[credentials]` | `totp_code_cmd` | Shell command that prints the current TOTP code |
| `[dns_servers]` | `primary` / `secondary` | VPN DNS server IPs |
| `[search_domains]` | `domains` | Comma-separated corporate search domains |
| `[routing_domains]` | `domains` | Domains forwarded to VPN DNS (usually same as above) |

## Files

| File | Purpose |
|---|---|
| `openconnect_pexpect_nc.py` | Main connection script |
| `config/vpn.conf` | All environment-specific configuration |
| `bash_commands/totp_command.sh` | Example TOTP wrapper using oathtool + secret-tool |

## Security notes

- `config/vpn.conf` ships with placeholder values only — no real credentials
- If you store a plain-text password in the config, run `chmod 600 config/vpn.conf`
- The keyring approach (Option A) keeps secrets off disk entirely
- The sudoers rule should be scoped to `/usr/sbin/openconnect` only
