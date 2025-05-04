# GetWeakExplicitMappings

ESC14 is an ADCS privilege escalation vector that can be introduced by the presence of weak explicit certificate mappings.

The goal of this tool is to enumerate weak explicit mappings through an Active Directory Domain.

```
usage: 

	 ▄████  █     █░▓█████  ███▄ ▄███▓
	 ██▒ ▀█▒▓█░ █ ░█░▓█   ▀ ▓██▒▀█▀ ██▒
	▒██░▄▄▄░▒█░ █ ░█ ▒███   ▓██    ▓██░
	░▓█  ██▓░█░ █ ░█ ▒▓█  ▄ ▒██    ▒██ 
	░▒▓███▀▒░░██▒██▓ ░▒████▒▒██▒   ░██▒
	 ░▒   ▒ ░ ▓░▒ ▒  ░░ ▒░ ░░ ▒░   ░  ░
	  ░   ░   ▒ ░ ░   ░ ░  ░░  ░      ░ 

Enumerate weak explicit mappings present within an Active Directory domain

options:
  -h, --help            show this help message and exit
  --dc-host DC_HOST     Domain Controller hostname/IP
  --domain DOMAIN, -d DOMAIN
                        Domain Name
  --username USERNAME, -u USERNAME
                        Username for LDAP auth
  --password PASSWORD, -p PASSWORD
                        Password for LDAP Auth
  --nt-hash NT_HASH, -H NT_HASH
                        NT hash for LDAP auth
  --scheme {ldap,ldaps}
                        LDAP scheme (Default : ldaps)
```
