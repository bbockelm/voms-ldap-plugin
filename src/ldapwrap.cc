
#define LDAP_DEPRECATED 1
#include "ldapwrap.h"

#include <errno.h>
#include <string.h>

#include <sstream>

extern "C" {
#include <openssl/x509.h>
#include <ldap.h>
}


ldapinterface::ldapinterface()
  : m_connected(false),
    m_errno(0),
    m_ldap(NULL)
{}


ldapinterface::~ldapinterface()
{
    if (m_connected) {
        close();
    }
}


bool
ldapinterface::connect(const char * dbname,
                       const char * hostname,
                       const char * user,
                       const char * password)
{
    if (m_ldap) {
        close();
    }
    int retval = ldap_initialize(&m_ldap, hostname);
    if (retval)
    {
        m_errno = ERR_DBERR;
        m_err = "Failed to initialize ldap connection: ";
        m_err = strerror(retval);
        m_ldap = NULL;
        return false;
    }
    int v3 = LDAP_VERSION3;
    retval = ldap_set_option(m_ldap, LDAP_OPT_PROTOCOL_VERSION, &v3);
    if (retval)
    {
        m_errno = ERR_DBERR;
        m_err = ldap_err2string(retval);
        close();
        return false;
    }

    retval = ldap_simple_bind_s(m_ldap, "", "");
    if (retval) {
        m_err = "Failure in bind; ";
        m_err += ldap_err2string(retval);
        m_errno = ERR_DBERR;
        return false;
    }
    m_base = user;
    m_hostname = hostname;
    m_db = dbname;
    m_password = password;
    return true;
}


bool
ldapinterface::reconnect()
{
    close();
    return connect(m_db.c_str(), m_hostname.c_str(), m_base.c_str(), m_password.c_str());
}

void
ldapinterface::close(void)
{
    if (!m_ldap) {return;}

    int retval = ldap_unbind_s(m_ldap);
    if (retval)
    {
        m_err = ldap_err2string(retval);
        m_errno = ERR_DBERR;
        m_ldap = NULL;
        return;
    }
    m_ldap = NULL;
}

signed long int
ldapinterface::getUID(X509 *cert)
{
    if (!m_ldap)
    {
        m_errno = ERR_NO_DB;
        m_err = "LDAP not connected";
    }
    char *dn = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (!dn)
    {
        m_errno = ERR_X509;
        m_err = "Unable to parse subject line";
        return -1;
    }
    int retval = getUID(dn);
    free(dn);
    return retval;
}


signed long int
ldapinterface::getUID(const char *dn)
{
    std::stringstream ss;
    ss << "(gridX509subject=" << dn << ")";
    std::string filter = ss.str();
    static char employeeNumber[] = "employeeNumber";
    char *attrs[2];
    attrs[0] = employeeNumber;
    attrs[1] = NULL;
    static const int scope = LDAP_SCOPE_ONELEVEL;
    LDAPMessage *msg = NULL;
    int retval = ldap_search_ext_s(m_ldap, m_base.c_str(), scope, filter.c_str(), attrs, 0, NULL, NULL, NULL, -1, &msg);
    if (retval)
    {
        m_err = ldap_err2string(retval);
        m_errno = ERR_DBERR;
        return -1;
    }
    retval = ldap_count_messages(m_ldap, msg);
    if (-1 == retval)
    {
        m_errno = ERR_DBERR;
        m_err = "Failed to retrieve all LDAP responses";
        close();
        return -1;
    }
    else if (retval == 0) {return -1;}

    LDAPMessage *result = ldap_first_message(m_ldap, msg);
    if (result == NULL)
    {
        m_errno = ERR_DBERR;
        m_err = "Failed to retrieve LDAP result";
        close();
        return -1;
    }

    retval = -1;
    BerElement *ber = NULL;
    for (char *attr = ldap_first_attribute(m_ldap, result, &ber); 
        attr != NULL; 
        attr = ldap_next_attribute(m_ldap, result, ber))
    {
        if (strcmp(attr, employeeNumber) == 0)
        {
/*
            struct berval **bvals = ldap_get_values_len(m_ldap, result, attr);
            if (bvals)
            {
                for (int idx = 0; bvals[idx] != NULL; idx++)
                {
                    BerElement *be = ber_alloc_t(LBER_USE_DER);
                    ber_init2(be, bvals[idx], LBER_USE_DER);
                    ber_int_t id;
                    ber_tag_t tag = ber_get_int(be, &id);
                    if (tag == static_cast<ber_tag_t>(-1))
                    {
                        fprintf(stderr, "Failed to decode employeeNumber: %s\n", bvals[idx]->bv_val);
                    }
                    else
                    {
                        printf("%s: %d\n", attr, id);
                    }
                    ber_free(be, 0);
                }
                ldap_value_free_len(bvals);
            }
*/
            char **vals;
            if ((vals = ldap_get_values(m_ldap, result, attr)) != NULL)
            {
                for (int idx = 0; vals[idx] != NULL; idx++)
                {
                    //printf("%s: %s\n", attr, vals[idx]);
                    if (*vals[idx] == '\0')
                    {
                        //printf("Skipping empty attribute value.\n");
                        continue;
                    }
                    char *endptr = NULL;
                    errno = 0;
                    long int ldapVal = strtol(vals[idx], &endptr, 10);
                    if (errno)
                    {
                        //printf("Failed to convert string to integer\n");
                        continue;
                    }
                    if (*endptr != '\0')
                    {
                        //printf("Unparsed characters in string; skipping.\n");
                        continue;
                    }
                    retval = ldapVal;
                    break;
                }
                ldap_value_free(vals);
            }
        }
        ldap_memfree(attr);
    }
    if (ber) {ber_free(ber, 0);}
    ldap_msgfree(msg);

    return retval;
}


bool ldapinterface::operation(int operation, void *result, ...)
{
  va_list va;
  va_start(va, result);

  clearError();
  int counter = 0;
  bool error = false;

  if (!result || !isConnected())
  {
    m_errno = ERR_NO_DB;
    m_err = "Database is not currently connected.\n";
    return false;
  }

  std::vector<std::string> *fqans = ((std::vector<std::string> *)result);
  X509 *cert = NULL;
  signed long int uid = -1;
  char *group = NULL;
  char *role = NULL;

  error = false;
  /* Parse parameters: */
  switch(operation) {
  case OPERATION_GET_GROUPS_AND_ROLE:
  case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
    uid = va_arg(va, signed long int);
    group = va_arg(va, char *);
    role = va_arg(va, char *);
    if (uid == -1 || !group || !role)
      error = true;
    break;

  case OPERATION_GET_ROLE:
  case OPERATION_GET_ROLE_ATTRIBS:
    uid = va_arg(va, signed long int);
    role = va_arg(va, char *);
    if (uid == -1 || !role)
      error = true;
    break;

  case OPERATION_GET_GROUPS:
  case OPERATION_GET_ALL:
  case OPERATION_GET_GROUPS_ATTRIBS:
  case OPERATION_GET_ALL_ATTRIBS:
    uid = va_arg(va, signed long int);
    if (uid == -1)
      error = true;
    break;

  case OPERATION_GET_VERSION:
    break;

  case OPERATION_GET_USER:
    cert = va_arg(va, X509 *);
    if (!cert)
      error = true;
    break;

  default:
    error = true;
  }
  va_end(va);

  if (error) {
    m_errno = ERR_NO_PARAM;
    m_err = "Required parameter to sqliface::operation() is missing!";
    return false;
  }

  do {
    error = false;
    switch(operation) {
    case OPERATION_GET_VERSION:
      {
        *((int *)result) = getVersion();
        return true;
      }
      break;

    case OPERATION_GET_USER:
      {
        signed long int res = getUID(cert);
        *((signed long int *)result) = res;
        if (res == -1)
          return false;
        return true;
      }
      break;

    case OPERATION_GET_ALL:
    case OPERATION_GET_GROUPS:
    case OPERATION_GET_ROLE:
    case OPERATION_GET_GROUPS_AND_ROLE:
      {
        if (uid > 0) {fqans->push_back(m_db);}

      }
      break;

    case OPERATION_GET_ALL_ATTRIBS:
    case OPERATION_GET_GROUPS_ATTRIBS:
    case OPERATION_GET_ROLE_ATTRIBS:
    case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
      // No attributes.
      break;
    }

    if (!error)
      break;
    else if (counter == 0) {
      clearError();
      reconnect();
      counter++;
    } else {
      break;
    }
  } while(true);

  return !error;
}

extern "C" {

sqliface::interface *CreateDB()
{
  return new ldapinterface();
}

int getDBInterfaceVersion()
{
    return 3;
}

int getDBInterfaceVersionMinor()
{
  return 1;
}

}

