
cmake_minimum_required( VERSION 2.6 )
project( voms-ldap-plugin )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( OpenLdap REQUIRED )
find_package( OpenSSL REQUIRED )

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()

include_directories( "${PROJECT_SOURCE_DIR}" "${OPENLDAP_INCLUDES}" ${OPENSSL_INCLUDE_DIR} )
add_library(LdapVoms MODULE src/dbwrap.h src/ldapwrap.h src/ldapwrap.cc)
target_link_libraries(LdapVoms ${OPENLDAP_LIB} ${OPENSSL_LIBRARIES} )

add_executable(test_main src/test_main.cc src/ldapwrap.h src/ldapwrap.cc src/dbwrap.h)
target_link_libraries(test_main ${OPENLDAP_LIB} ${OPENSSL_LIBRARIES} )

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
  SET(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(
  TARGETS LdapVoms
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/voms )

set_target_properties(
  LdapVoms
  PROPERTIES
  LINK_INTERFACE_LIBRARIES "" )


