# Authors: Howard Guo <hguo@suse.com>
# Copyright (C) 2015 SUSE Linux GmbH
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ipaplatform.base.paths import BasePathNamespace

class SusePathNamespace(BasePathNamespace):
    SYSTEMCTL = "/usr/bin/systemctl"
    ETC_HTTPD_DIR = "/etc/apache2"
    HTTPD = "/usr/sbin/httpd2"
    HTTPD_ALIAS_DIR = "/etc/apache2/ipa"
    ALIAS_CACERT_ASC = "/etc/apache2/ipa/cacert.asc"
    ALIAS_PWDFILE_TXT = "/etc/apache2/ipa/pwdfile.txt"
    LIBSOFTHSM2_SO_64 = "/usr/lib64/pkcs11/libsofthsm2.so"
    HTTPD_CONF_D_DIR = "/etc/apache2/conf.d/"
    HTTPD_IPA_PKI_PROXY_CONF = "/etc/apache2/conf.d/ipa-pki-proxy.conf"
    HTTPD_IPA_REWRITE_CONF = "/etc/apache2/conf.d/ipa-rewrite.conf"
    HTTPD_IPA_CONF = "/etc/apache2/conf.d/ipa.conf"
    HTTPD_NSS_CONF = "/etc/apache2/conf.d/mod_nss.conf"
    HTTPD_SSL_CONF = "/etc/apache2/conf.d/ssl.conf"
    IPA_KEYTAB = "/etc/apache2/ipa/ipa.keytab"
    HTTPD_PASSWORD_CONF = "/etc/apache2/ipa/password.conf"
    NAMED_MANAGED_KEYS_DIR = "/var/lib/named/dyn"
    SYSCONFIG_HTTPD = "/etc/sysconfig/apache2"
    SYSCONFIG_NTPD = "/etc/sysconfig/ntp"
    UPDATE_CA_TRUST = "/usr/sbin/update-ca-certificates"
    IPA_SERVER_GUARD = "/usr/lib/certmonger/ipa-server-guard"
    IPA_DNSKEYSYNCD_REPLICA = "/usr/lib/ipa/ipa-dnskeysync-replica"
    IPA_DNSKEYSYNCD = "/usr/lib/ipa/ipa-dnskeysyncd"
    IPA_ODS_EXPORTER = "/usr/lib/ipa/ipa-ods-exporter"
    DNSSEC_KEYFROMLABEL = "/usr/sbin/dnssec-keyfromlabel"
    NAMED_PKCS11 = "/usr/sbin/named"
    VAR_KERBEROS_KRB5KDC_DIR = "/var/lib/kerberos/krb5kdc/"
    VAR_KRB5KDC_K5_REALM = "/var/lib/kerberos/krb5kdc/.k5."
    CACERT_PEM = "/var/lib/kerberos/krb5kdc/cacert.pem"
    KRB5KDC_KDC_CONF = "/var/lib/kerberos/krb5kdc/kdc.conf"
    KDC_PEM = "/var/lib/kerberos/krb5kdc/kdc.pem"
    VAR_LOG_HTTPD_DIR = "/var/log/apache2"
    NAMED_VAR_DIR = "/var/lib/named"
    NAMED_ROOT_KEY = "named.root.key" # Intentionally using relative path
    BIND_LDAP_DNS_IPA_WORKDIR = "/var/lib/named/dyndb-ldap/ipa/"
    BIND_LDAP_DNS_ZONE_WORKDIR = "/var/lib/named/dyndb-ldap/ipa/master/"
    BIND_LDAP_SO = "/usr/lib/bind/ldap.so"
    BIND_LDAP_SO_64 = "/usr/lib64/bind/ldap.so"
    KDESTROY = "/usr/lib/mit/bin/kdestroy"
    KINIT = "/usr/bin/kinit"
    IPA_KEYTAB = "/etc/apache2/ipa/ipa.keytab"
    SYSTEMWIDE_IPA_CA_CRT = "/etc/pki/trust/anchors/ipa-ca.crt"
    CA_CRT = "/etc/apache2/ipa/ca.crt"
    BIN_KVNO = "/usr/lib/mit/bin/kvno"
    # volatile files
    VAR_RUN_DIRSRV_DIR = "/run/dirsrv"
    IPA_RENEWAL_LOCK = "/run/ipa/renewal.lock"
    SVC_LIST_FILE = "/run/ipa/services.list"
    SVC_LIST_DIR = "/run/ipa"
    KRB5CC_SAMBA = "/run/samba/krb5cc_samba"
    SLAPD_INSTANCE_SOCKET_TEMPLATE = "/run/slapd-%s.socket"
    ALL_SLAPD_INSTANCE_SOCKETS = "/run/slapd-*.socket"
    IPA_MEMCACHED_DIR = "/run/ipa_memcached"
    VAR_RUN_IPA_MEMCACHED = "/run/ipa_memcached/ipa_memcached"
    # I am not very confident about this
    IPA_NSSDB_DIR = HTTPD_ALIAS_DIR

paths = SusePathNamespace()

