import ldap3, re, argparse
from ldap3 import Server, Connection, NTLM, ALL

parser = argparse.ArgumentParser(description='Enumerate weak explicit mappings present within an Active Directory domain',
usage=u''' GetWeakExplicitMappings.py [-h] --dc-host -d domain -u username [-p password | -H nt_hash] [--scheme (ldap|ldaps)]

         ▄████  █     █░▓█████  ███▄ ▄███▓
         ██▒ ▀█▒▓█░ █ ░█░▓█   ▀ ▓██▒▀█▀ ██▒
        ▒██░▄▄▄░▒█░ █ ░█ ▒███   ▓██    ▓██░
        ░▓█  ██▓░█░ █ ░█ ▒▓█  ▄ ▒██    ▒██ 
        ░▒▓███▀▒░░██▒██▓ ░▒████▒▒██▒   ░██▒
         ░▒   ▒ ░ ▓░▒ ▒  ░░ ▒░ ░░ ▒░   ░  ░
          ░   ░   ▒ ░ ░   ░ ░  ░░  ░      ░ 
''')
parser.add_argument("--dc-host", action="store", dest="dc_host", required=True, help="Domain Controller hostname/IP")
parser.add_argument("--domain", "-d", action="store", dest="domain", required=True, help="Domain Name")
parser.add_argument("--username", "-u", action="store", dest="username", required=True, help="Username for LDAP auth")
parser.add_argument("--password", "-p", action="store", dest="password", help="Password for LDAP Auth")
parser.add_argument("--nt-hash", "-H", action="store", dest="nt_hash", help="NT hash for LDAP auth")
parser.add_argument("--scheme", default="ldaps", choices=["ldap", "ldaps"], dest="scheme", help="LDAP scheme (Default : ldaps).")
args = parser.parse_args()

def ntlm_ldap_auth(user, pwd, hash, dom, dc_host, scheme):
  conn_url = f"{scheme}://{dc_host}"
  use_ssl = scheme == "ldaps"
  server = Server(conn_url, use_ssl=use_ssl, get_info=ALL)

  if not any([pwd, hash]): raise ValueError("[*] Choose either Password or NT hash for NTLM Authentication")
  if hash:
    if not re.match(r'[a-z0-9]{32}', hash):
      raise ValueError("[*] Invalid NT hash")
    pwd = f"aad3b435b51404eeaad3b435b51404ee:{hash}"
  try:
    with Connection(conn_url, user=f"{dom}\\{user}", password=pwd, authentication=NTLM, auto_bind=True) as conn:
      if not use_ssl: conn.start_tls()
      print("[+] Connecion OK")
      return conn
  except Exception as e:
    print(f"[*] LDAP authentication failed : {e}")
    exit(-1)

conn = ntlm_ldap_auth(args.username, args.password, args.nt_hash, args.domain, args.dc_host, args.scheme)

# Query all the altSecurityIdentities
conn.search(
  search_base=",".join(["DC="+i for i in args.domain.split('.')]),
  search_filter="(samaccountname=*)",
  attributes=["altSecurityIdentities","distinguishedName"]
)

#print(conn.result)
# Gathers the pairs (altSecurityIdentities:destinguishedName)
altsec = []
for i in conn.response:
  try:
    altsec.append((
      i["attributes"]["altSecurityIdentities"],
      i["attributes"]["distinguishedName"]
    ))
  except: pass

# Prints all the weak ones (<I>..<S>|<S>...|<RFC822>...)
for i in altsec:
  a = [j for j in i[0] if re.match("(?!(X509:<(SKI|SHA1-PUKEY)>|X509:<I>.*<SR>))", j)]
  if a != []:
    print("[+]",i[1])
    for j in a: print("   -", j)
conn.unbind()
