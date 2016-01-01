
#include "ldapwrap.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: test_main connect_uri ldap_base_dn user_dn");
        return 1;
    }
    const char *connect_uri = argv[1];
    const char *ldap_base_dn = argv[2];
    const char *user_dn = argv[3];
    ldapinterface ld;
    ld.connect("/ligo", connect_uri, ldap_base_dn, "");
    if (ld.error())
    {
        printf("Failed to connect to server (%d): %s\n", ld.error(), ld.errorMessage());
        return 1;
    }
    long id = ld.getUID(user_dn);
    if (id >= 0)
    {
        printf("Returned ID is %ld\n", id);
    }
    else if (ld.error())
    {
        printf("Failure (%d): %s\n", ld.error(), ld.errorMessage());
        return 1;
    }
    else
    {
        printf("Unknown failure.\n");
        return 1;
    }
    return 0;
}

