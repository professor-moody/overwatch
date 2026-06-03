# Operator Tool Prerequisites

Overwatch is a state and reasoning layer — it does not bundle the offensive
tools it orchestrates. The operator's machine needs the right tools installed
locally before the first scan, or the AI will get back `command not found` and
have to guess what to suggest.

The fastest path: install the group(s) below that match the engagement you
plan to run, then verify with the [`check_tools`](tools/check-tools.md) MCP
tool.

!!! tip "Don't install everything you don't need"
    Pick the group for your engagement type. AD-internal engagements need
    almost nothing from the cloud group. CTF / lab work usually only needs
    the network + cracking groups.

## Active Directory engagements

Required for `nxc` / `kerbrute` / `certipy` / `secretsdump` / BloodHound
workflows:

- `nmap`
- `netexec` (formerly CrackMapExec — `nxc`)
- `kerbrute`
- `impacket-suite` (`secretsdump.py`, `GetUserSPNs.py`, `GetNPUsers.py`,
  `psexec.py`, `wmiexec.py`, `getST.py`)
- `certipy-ad` (ADCS / ESC* abuse)
- `bloodhound-python` or `bloodhound.py` (collector)
- `ldapsearch` (often already present on Linux/macOS)
- `enum4linux-ng`
- `responder` (LLMNR / NBNS / MDNS capture; root required)
- `evil-winrm` (WinRM admin shells)

Install on macOS (Homebrew + pipx):

```bash
brew install nmap ldapsearch
pipx install netexec impacket certipy-ad kerbrute bloodhound bloodhound-cli
pipx install evil-winrm-py  # or: gem install evil-winrm
```

Install on Kali / Debian:

```bash
sudo apt install -y nmap ldap-utils enum4linux-ng responder
pipx install netexec impacket certipy-ad kerbrute bloodhound bloodhound-cli evil-winrm
```

## Web / external engagements

Required for `sqlmap`, `nuclei`, `burp`, `zap`, and directory enumeration:

- `nmap`
- `sqlmap`
- `nuclei` (Project Discovery)
- `ffuf` or `gobuster`
- `nikto`
- `wpscan` (WordPress)
- `testssl.sh`

Install on macOS:

```bash
brew install nmap sqlmap ffuf gobuster nikto wpscan
pipx install nuclei  # or: brew install nuclei
# testssl: clone https://github.com/drwetter/testssl.sh
```

Install on Kali / Debian:

```bash
sudo apt install -y nmap sqlmap ffuf gobuster nikto wpscan nuclei testssl.sh
```

## Cloud engagements

Required for AWS, Azure, GCP, GitHub, and Okta workflows:

- `aws` (AWS CLI v2)
- `az` (Azure CLI)
- `gcloud` (Google Cloud SDK)
- `gh` (GitHub CLI)
- `jq`
- `cloudfox`
- `microburst` (Azure recon, PowerShell module)
- `scoutsuite`
- `roadrecon` (Azure AD)

Install on macOS:

```bash
brew install awscli azure-cli google-cloud-sdk gh jq
pipx install scoutsuite roadrecon
# cloudfox: https://github.com/BishopFox/cloudfox/releases
```

Install on Kali / Debian:

```bash
sudo apt install -y awscli azure-cli google-cloud-sdk gh jq
pipx install scoutsuite roadrecon
```

## Credential cracking

- `hashcat` (GPU recommended)
- `john` (`john-jumbo` / `john-the-ripper`)

Install on macOS:

```bash
brew install hashcat john-jumbo
```

Install on Kali / Debian:

```bash
sudo apt install -y hashcat john
```

## Optional: local PTY sessions

`node-pty` is an optional native dependency used for `local_pty` sessions. It
requires Python 3 and a C++ compiler. If it fails to install during
`npm install`, Overwatch will work normally — only local PTY sessions are
unavailable. Use `ssh_session` against the target instead.

## Verify with `check_tools`

After installing, ask Claude:

> "Run check_tools to confirm everything Overwatch needs is on PATH."

The MCP tool walks the operator-tools catalog, runs each tool's `--version`
or equivalent probe, and reports missing or stale binaries. This is the
canonical preflight — there is no need to maintain a manual checklist after
the initial install.

If `check_tools` flags something missing for an engagement type you do not
plan to run, ignore it — every tool is opt-in and lazy-loaded.

## What if I forget a tool mid-engagement?

The Bash hook at `.claude/hooks/overwatch-bash-guard.mjs` blocks raw
target-facing commands that bypass Overwatch's wrappers, so a missing tool
typically surfaces as a clear `not found` error from the wrapper rather than
silent failure. Install the missing tool, then re-ask Claude to retry — the
state in the graph is preserved across the gap.
