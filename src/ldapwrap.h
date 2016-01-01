#include "dbwrap.h"

#include <string>
#include <vector>

extern "C" {
#include <openssl/x509.h>
#include <ldap.h>
}

class ldapinterface : public sqliface::interface
{
public:

  ldapinterface();
  ~ldapinterface(void);

  bool connect(const char * dbname,
               const char * hostname,
               const char * user,
               const char * password);

  int error(void) const {return m_errno;}
  bool reconnect();
  void close(void);
  bool setOption(int, void *) {return true;}

  bool operation(int operation_type, void *result, ...);

  bool isConnected(void) {return m_ldap;}
  char *errorMessage(void) {return const_cast<char *>(m_err.c_str());}

  sqliface::interface *getSession() {if (!isConnected()) {reconnect();} return this;}
  void releaseSession(sqliface::interface *iface) {iface->close();}

  signed long int getUID(const char *);

private:

  signed long int getUID(X509 *);

  void clearError() {m_err = ""; m_errno = 0;}
  int getVersion() const {return 3;}

  bool m_connected;
  int m_errno;

  std::string m_hostname;
  std::string m_db;
  std::string m_password;
  std::string m_err;
  std::string m_base;

  LDAP *m_ldap;
};

