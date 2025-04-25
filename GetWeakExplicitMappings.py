import ldap3, re, argparse

parser = argparse.ArgumentParser(description="""
 Enumerate weak explicit mappings present within an Active Directory domain
""")
parser.add_argument("-dc-host", action="store", dest="dc_host", required=True)
parser.add_argument("-domain", action="store", dest="domain", required=True)
parser.add_argument("-u", action="store", dest="username", required=True)
parser.add_argument("-p", action="store", dest="attacker_password", required=True)
args = parser.parse_args()

# Server/User Informations
server = ldap3.Server(args.dc_host)
attacker_username = args.domain+"\\"+args.username

# LDAP connection
conn = ldap3.Connection(
    server=server,
    user=attacker_username,
    password=args.attacker_password,
    authentication=ldap3.NTLM
)
conn.bind()

# Query all the altSecurityIdentities
conn.search(
        search_base="DC=administrator,DC=htb",
        search_filter="(samaccountname=*)",
        attributes=["altSecurityIdentities","distinguishedName"]
)

# Gathers the pairs (altSecurityIdentities:destinguishedName)
altsec = []
for resp in conn.response:
 try:
  altsec.append((
        resp["attributes"]["altSecurityIdentities"],
        resp["attributes"]["distinguishedName"]
  ))
 except: pass

# Prints all the weak ones (<I>..<S>|<S>...|<RFC822>...)
for tpl in altsec:
 ids = [sec for sec in tpl[0] if re.match("(?!(X509:<(SKI|SHA1-PUKEY)>|X509:<I>.*<SR>))", sec)]
 if ids != []:
  print("[+]",tpl[1])
  for sec in ids: print("   -", sec)
conn.unbind()
