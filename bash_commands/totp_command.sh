#!/bin/bash
# Example TOTP code generator using oathtool + libsecret keyring.
# The secret-tool key name must match what you stored with:
#   secret-tool store --label='VPN TOTP' totp <your_totp_key>
#
# Point totp_code_cmd in config/vpn.conf at this script, or inline the
# command directly in the config without using this wrapper.

TOTP_KEY="totp_vpn"  # change to match your secret-tool key

oathtool --totp --base32 "$(secret-tool lookup totp "$TOTP_KEY")"
