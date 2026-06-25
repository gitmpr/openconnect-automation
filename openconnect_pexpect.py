#!/usr/bin/env python3
"""
Noninteractive VPN connection via OpenConnect + pexpect.
All site-specific settings are read from a config file, by default
~/.config/openconnect-automation/vpn.conf (override with the
OPENCONNECT_AUTOMATION_CONFIG environment variable).
Credentials are retrieved either from the keyring (via a shell command)
or from a plain-text value in the config file.
"""
import argparse
import pexpect
import subprocess
import sys
import os
import signal
import re
import configparser
import time
from pathlib import Path

CONFIG_FILE = Path(os.environ.get(
    "OPENCONNECT_AUTOMATION_CONFIG",
    Path.home() / ".config" / "openconnect-automation" / "vpn.conf"))


class Colors:
    CYAN   = '\033[36m'
    GREEN  = '\033[32m'
    YELLOW = '\033[33m'
    RED    = '\033[31m'
    BOLD   = '\033[1m'
    END    = '\033[0m'


def log_info(msg):    print(f"{Colors.CYAN}[INFO] {msg}{Colors.END}", flush=True)
def log_warn(msg):    print(f"{Colors.YELLOW}[WARN] {msg}{Colors.END}", flush=True)
def log_error(msg):   print(f"{Colors.RED}[ERROR] {msg}{Colors.END}", flush=True)
def log_success(msg): print(f"{Colors.GREEN}[SUCCESS] {msg}{Colors.END}", flush=True)


class FilteredOutput:
    """Tee openconnect output to stdout.

    The openconnect command always runs with --dump-http-traffic so that pexpect
    can match the HTML body (locked account, expired password, rejected cookie).
    That matching reads from child.before/buffer and is independent of this
    logfile, so we can freely suppress the noisy HTTP dump lines from display.

    Unless debug is set, dump lines (request lines '> ' and response lines '< ')
    are dropped; openconnect's own progress lines pass through. With debug, every
    line is shown.
    """

    def __init__(self, debug=False):
        self.debug = debug
        self._buf = ""

    def _suppressed(self, line):
        return not self.debug and (line.startswith('< ') or line.startswith('> '))

    def write(self, data):
        self._buf += data
        while '\n' in self._buf:
            line, self._buf = self._buf.split('\n', 1)
            if not self._suppressed(line):
                sys.stdout.write(line + '\n')
        sys.stdout.flush()

    def flush(self):
        if self._buf and not self._suppressed(self._buf):
            sys.stdout.write(self._buf)
            self._buf = ""
        sys.stdout.flush()


# openconnect data-phase log lines that are pure per-packet noise during a
# connected session (the tunnel keeps logging these as traffic flows). These
# appear during child.interact(), not the auth handshake, so they are filtered
# separately from the HTTP dump above. Kept narrow so genuine session events
# (reconnects, DPD, errors) are never hidden.
_INTERACT_NOISE = (
    re.compile(rb'^(Incoming|Sending) KMP message \d+ of size \d+'),
)


class InteractFilter:
    """output_filter for child.interact(): drop openconnect's data-phase noise.

    pexpect always hands interact filters raw bytes (even with encoding set), so
    this buffers by line and works on bytes. Unless debug is set, lines matching
    _INTERACT_NOISE are dropped; everything else passes through unchanged.
    """

    def __init__(self, debug=False):
        self.debug = debug
        self._buf = b""

    def __call__(self, data):
        if self.debug:
            return data
        self._buf += data
        out = []
        while b'\n' in self._buf:
            line, self._buf = self._buf.split(b'\n', 1)
            if not any(p.search(line) for p in _INTERACT_NOISE):
                out.append(line + b'\n')
        return b"".join(out)


def check_already_running():
    proc = subprocess.run(["pgrep", "-a", "openconnect"], capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        pid_line = proc.stdout.strip().splitlines()[0]
        return True, f"openconnect already running (pid {pid_line.split()[0]})"

    tun = subprocess.run(["ip", "link", "show", "tun0"], capture_output=True, text=True, check=False)
    if tun.returncode == 0:
        return True, "tun0 interface already exists"

    return False, ""


def load_config():
    if not CONFIG_FILE.exists():
        log_error(f"Config file not found: {CONFIG_FILE}")
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config


def get_credential(config, section, plain_key, cmd_key, label):
    has_plain = config.has_option(section, plain_key)
    has_cmd   = config.has_option(section, cmd_key)

    if has_plain and has_cmd:
        log_error(f"Ambiguous {label} config: set either '{plain_key}' or '{cmd_key}' in [{section}], not both.")
        sys.exit(1)
    if not has_plain and not has_cmd:
        log_error(f"No {label} configured. Set either '{plain_key}' or '{cmd_key}' in [{section}].")
        sys.exit(1)

    if has_plain:
        return config.get(section, plain_key)

    cmd = config.get(section, cmd_key)
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        log_error(f"Command for {label} failed: {e}")
        sys.exit(1)


def get_totp_code(config):
    has_secret = config.has_option('credentials', 'totp_secret')
    has_cmd    = config.has_option('credentials', 'totp_code_cmd')

    if has_secret and has_cmd:
        log_error("Ambiguous TOTP config: set either 'totp_secret' or 'totp_code_cmd' in [credentials], not both.")
        sys.exit(1)
    if not has_secret and not has_cmd:
        log_error("No TOTP method configured. Set either 'totp_secret' or 'totp_code_cmd' in [credentials].")
        sys.exit(1)

    if has_secret:
        secret = config.get('credentials', 'totp_secret')
        try:
            return subprocess.check_output(
                ["oathtool", "--totp", "--base32", secret], text=True
            ).strip()
        except subprocess.CalledProcessError as e:
            log_error(f"oathtool failed: {e}")
            sys.exit(1)

    cmd = config.get('credentials', 'totp_code_cmd')
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        log_error(f"TOTP command failed: {e}")
        sys.exit(1)


def backup_dns_state():
    try:
        result = subprocess.run(["resolvectl", "status"], capture_output=True, text=True)
        with open("/tmp/systemd-resolved.vpn.backup", "w") as f:
            f.write(result.stdout)
        log_info("Backed up systemd-resolved DNS state")
    except Exception as e:
        log_warn(f"Could not back up DNS state: {e}")


def restore_dns_state():
    try:
        tun_check = subprocess.run(["ip", "addr", "show", "tun0"],
                                   capture_output=True, text=True, check=False)
        if tun_check.returncode == 0:
            revert = subprocess.run(["resolvectl", "revert", "tun0"],
                                    capture_output=True, text=True, check=False)
            if revert.returncode == 0:
                log_info("Reset VPN interface DNS configuration")
            else:
                log_warn(f"Could not reset VPN interface: {revert.stderr.strip()}")
        else:
            log_info("VPN interface already removed (normal during disconnect)")

        target = subprocess.run(["readlink", "/etc/resolv.conf"],
                                capture_output=True, text=True, check=False).stdout.strip()
        if target != "/run/systemd/resolve/stub-resolv.conf":
            log_warn("/etc/resolv.conf is not pointing to systemd-resolved")
            log_info("To fix manually:")
            log_info("  sudo rm -f /etc/resolv.conf")
            log_info("  sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf")
        else:
            log_info("resolv.conf correctly points to systemd-resolved")
    except Exception as e:
        log_warn(f"Could not restore DNS state: {e}")


def configure_vpn_dns(config):
    log_info("Configuring VPN DNS via systemd-resolved...")
    try:
        time.sleep(2)

        tun_check = subprocess.run(["ip", "addr", "show", "tun0"],
                                   capture_output=True, text=True, check=False)
        if tun_check.returncode != 0:
            log_warn("tun0 interface not found - DNS configuration skipped")
            return False

        if not config.has_section('dns_servers'):
            log_info("No [dns_servers] configured - skipping DNS configuration")
            return False

        vpn_dns = [config.get('dns_servers', 'primary'),
                   config.get('dns_servers', 'secondary')]

        dns_result = subprocess.run(["resolvectl", "dns", "tun0"] + vpn_dns,
                                    capture_output=True, text=True, check=False)
        if dns_result.returncode != 0:
            log_error(f"Failed to set VPN DNS servers: {dns_result.stderr.strip()}")
            return False
        log_success(f"Set VPN DNS servers: {vpn_dns}")

        if config.has_section('search_domains') and config.has_option('search_domains', 'domains'):
            domains = [d.strip() for d in config.get('search_domains', 'domains').split(',')]
            all_domains = [f"~{d}" for d in domains] + domains
            domain_result = subprocess.run(["resolvectl", "domain", "tun0"] + all_domains,
                                           capture_output=True, text=True, check=False)
            if domain_result.returncode != 0:
                log_error(f"Failed to set VPN domains: {domain_result.stderr.strip()}")
                return False
            log_success(f"Set {len(domains)} routing/search domains on tun0")
        else:
            log_info("No [search_domains] configured - skipping domain routing")

        verify = subprocess.run(["resolvectl", "status", "tun0"],
                                capture_output=True, text=True, check=False)
        if verify.returncode == 0:
            log_success("VPN DNS configuration applied")
            for line in verify.stdout.split('\n'):
                if 'DNS Servers:' in line or 'DNS Domain:' in line:
                    log_info(f"  {line.strip()}")

    except Exception as e:
        log_error(f"Unexpected error configuring DNS: {e}")
        return False
    return True


def send_masked(child, label, secret, log_filter):
    print(f"\n{Colors.YELLOW}[INPUT] {label:<15}: {'*' * 8}{Colors.END}", flush=True)
    child.logfile = None
    child.sendline(secret)
    child.logfile = log_filter


def parse_sessions(output):
    sessions = []
    for line in output.split('\n'):
        if line.strip().startswith('- '):
            match = re.search(r'- ([a-f0-9]{8}) from (.+?) at (.+)', line.strip())
            if match:
                sessions.append({
                    'id': match.group(1),
                    'ip': match.group(2),
                    'date': match.group(3),
                    'full_line': line.strip(),
                })
    return sessions


def signal_handler(sig, frame):
    log_info("Interrupt received, cleaning up...")
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(
        description="Noninteractive VPN connection via OpenConnect + pexpect.")
    parser.add_argument(
        "-d", "--debug", action="store_true",
        help="Show the full openconnect HTTP traffic dump (verbose). "
             "Locked-account / expired-password detection works either way.")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if os.geteuid() == 0:
        log_error("Do not run as root. The script escalates via sudo only when needed.")
        sys.exit(1)

    already_running, reason = check_already_running()
    if already_running:
        log_warn(f"VPN is already connected ({reason}).")
        log_info("Disconnect first with: sudo pkill openconnect")
        sys.exit(1)

    log_info(f"Running as user: {os.getenv('USER')}")

    config = load_config()

    vpn_server      = config.get('vpn', 'server')
    vpn_user        = config.get('vpn', 'username')
    openconnect_bin = config.get('vpn', 'openconnect_path')
    protocol        = config.get('vpn', 'protocol')

    backup_dns_state()

    ad_password = get_credential(config, 'credentials', 'ad_password', 'ad_password_cmd', 'AD password')
    log_info("Retrieved AD password")

    totp_code = get_totp_code(config)
    log_info("Retrieved TOTP code")

    # --dump-http-traffic is always on so pexpect can match the HTML body for
    # locked-account / expired-password / rejected-cookie detection. The dump
    # lines are suppressed from display unless --debug (see FilteredOutput).
    cmd = f"sudo {openconnect_bin} --protocol={protocol} --dump-http-traffic -u {vpn_user} {vpn_server}"
    log_info(f"Connecting: {cmd}")

    child = pexpect.spawn(cmd, encoding='utf-8', timeout=30)
    log_filter = FilteredOutput(debug=args.debug)
    child.logfile = log_filter

    try:
        while True:
            index = child.expect([
                r"password:",                           # 0: AD password prompt
                r"password#2:",                         # 1: TOTP prompt
                r"Session: \[.*\]:",                    # 2: Session selection prompt
                r"ESP session established with server", # 3: VPN success
                r"VPN tunnel connected",                # 4: VPN success (alt)
                r"Established connection",              # 5: VPN success (alt)
                r"Configured as \d+\.\d+\.\d+\.\d+",   # 6: NetConnect success
                r"Login failed",                        # 7: Login failure
                r"Unknown form.*frmChgPasswd",          # 8: Password change form
                r"p=passwordChange",                    # 9: Password change redirect
                pexpect.EOF,                            # 10
                pexpect.TIMEOUT,                        # 11
                r"account was locked",                  # 12: TOTP account locked (HTML body)
                r"Cookie was rejected",                 # 13: server rejected session cookie
            ], timeout=60)

            if index == 0:
                send_masked(child, "AD password", ad_password, log_filter)

            elif index == 1:
                send_masked(child, "TOTP code", totp_code, log_filter)

            elif index == 2:
                output = child.before + child.after
                sessions = parse_sessions(output)
                if sessions:
                    session_to_kill = sessions[0]['id']
                    log_info(f"Session limit reached - killing oldest session: {session_to_kill}")
                    child.sendline(session_to_kill)
                else:
                    log_error("Could not parse session IDs from output:")
                    print(output)
                    child.sendline("")

            elif index in (3, 4, 5, 6):
                print()
                log_info("VPN tunnel established successfully!")
                configure_vpn_dns(config)
                break

            elif index == 7:
                print()
                log_error("Login failed - check credentials")
                restore_dns_state()
                sys.exit(1)

            elif index in (8, 9):
                print()
                log_error("PASSWORD EXPIRED - password change required")
                log_info(f"Log in to {vpn_server} via a browser to change your password.")
                log_info("After changing, update the stored credential accordingly.")
                restore_dns_state()
                sys.exit(1)

            elif index == 10:
                log_info("VPN process ended.")
                break

            elif index == 11:
                log_warn("Timeout waiting for prompt - attempting DNS config anyway...")
                configure_vpn_dns(config)
                break

            elif index == 12:
                print()
                log_error("Login failed - TOTP account is locked.")
                restore_dns_state()
                sys.exit(1)

            elif index == 13:
                print()
                log_error("Server rejected the session cookie - authentication failed.")
                restore_dns_state()
                sys.exit(1)

    except KeyboardInterrupt:
        log_info("Interrupted during authentication.")
        child.close()
        restore_dns_state()
        sys.exit(0)

    log_info("VPN authenticated. Press Ctrl+C to disconnect.")

    try:
        child.logfile = None
        child.interact(output_filter=InteractFilter(debug=args.debug))

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[DISCONNECT]{Colors.END} Disconnecting VPN...")
        try:
            child.sendintr()
            child.expect(pexpect.EOF, timeout=5)
            log_info("OpenConnect terminated - VPN session closed.")
        except pexpect.TIMEOUT:
            log_warn("Graceful shutdown timed out, forcing termination...")
            child.terminate()
        except pexpect.EOF:
            log_info("OpenConnect process ended.")

    except Exception as e:
        log_error(f"Unexpected error during VPN session: {e}")
        child.terminate()

    finally:
        if child.isalive():
            child.close()
        restore_dns_state()
        log_info("VPN cleanup completed.")


if __name__ == "__main__":
    main()
