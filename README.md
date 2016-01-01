# voms-ldap-plugin
LDAP query plugin for VOMS server

This simple plugin allows authorizes VOMS users based on their
presence in a remote ldap server (as opposed to a SQL database).

# Example voms.conf
```
--code=15000
--dbname=/example.org
--logfile=/var/log/voms/voms.example.org
--loglevel=4
--logtype=7
--port=15000
--sqlloc=/usr/lib64/voms/libLdapVoms.so
--username=ou=people,dc=example,dc=org
--contactstring=ldap://ldap.example.org
--vo=example.org
--uri=hcc-briantest.unl.edu:15000
--timeout=2419200
--passfile=/etc/voms/ligo/voms.pass
--x509_user_cert=/etc/grid-security/voms/vomscert.pem
--x509_user_key=/etc/grid-security/voms/vomskey.pem
```

As plugins are limited in their ability to get arbitrary options from the server, the a few configuration parameters above are misused:
- The `dbname` parameter is actually used to set a default VOMS group name.
- The `passfile` is ignored by the plugin; LDAP SIMPLE auth is used instead (with no password).
- `username` is the base DN of the LDAP server to query.
