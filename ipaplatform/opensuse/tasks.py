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

import os
import stat
import socket
import sys
import urllib
import base64

from subprocess import CalledProcessError
from nss.error import NSPRError
from pyasn1.error import PyAsn1Error
from ipapython.ipa_log_manager import root_logger, log_mgr
from ipapython import ipautil
import ipapython.errors
from ipalib import x509
from ipaplatform.paths import paths
from ipaplatform.base.tasks import BaseTaskNamespace

log = log_mgr.get_logger(__name__)

class SuseTaskNamespace(BaseTaskNamespace):

    def restore_context(self, filepath, restorecon=paths.SBIN_RESTORECON):
        pass

    def check_selinux_status(self, restorecon=paths.RESTORECON):
        pass

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        print('FIXME: restore_pre_ipa_client_configuration is called')
        pass

    def set_nisdomain(self, nisdomain):
        print('FIXME: set_nisdomain is called')
        pass

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore):
        print('FIXME: modify_nsswitch_pam_stack is called')
        pass

    def modify_pam_to_use_krb5(self, statestore):
        print('FIXME: modify_pam_to_use_krb5 is called')
        pass

    # Credits to upstream developer
    def reload_systemwide_ca_store(self):
        try:
            ipautil.run([paths.UPDATE_CA_TRUST])
        except CalledProcessError as e:
            root_logger.error(
                "Could not update systemwide CA trust database: %s", e)
            return False
        else:
            root_logger.info("Systemwide CA database updated.")
            return True

    # Credits to upstream developer
    def insert_ca_certs_into_systemwide_ca_store(self, ca_certs):
        # pylint: disable=ipa-forbidden-import
        from ipalib import x509  # FixMe: break import cycle
        from ipalib.errors import CertificateError
        # pylint: enable=ipa-forbidden-import

        new_cacert_path = paths.SYSTEMWIDE_IPA_CA_CRT

        if os.path.exists(new_cacert_path):
            try:
                os.remove(new_cacert_path)
            except OSError as e:
                root_logger.error(
                    "Could not remove %s: %s", new_cacert_path, e)
                return False

        new_cacert_path = paths.IPA_P11_KIT

        try:
            f = open(new_cacert_path, 'w')
        except IOError as e:
            root_logger.info("Failed to open %s: %s" % (new_cacert_path, e))
            return False

        f.write("# This file was created by IPA. Do not edit.\n"
                "\n")

        has_eku = set()
        for cert, nickname, trusted, ext_key_usage in ca_certs:
            try:
                subject = cert.subject_bytes
                issuer = cert.issuer_bytes
                serial_number = cert.serial_number_bytes
                public_key_info = cert.public_key_info_bytes
            except (PyAsn1Error, ValueError, CertificateError) as e:
                root_logger.warning(
                    "Failed to decode certificate \"%s\": %s", nickname, e)
                continue

            label = urllib.parse.quote(nickname)
            subject = urllib.parse.quote(subject)
            issuer = urllib.parse.quote(issuer)
            serial_number = urllib.parse.quote(serial_number)
            public_key_info = urllib.parse.quote(public_key_info)

            obj = ("[p11-kit-object-v1]\n"
                   "class: certificate\n"
                   "certificate-type: x-509\n"
                   "certificate-category: authority\n"
                   "label: \"%(label)s\"\n"
                   "subject: \"%(subject)s\"\n"
                   "issuer: \"%(issuer)s\"\n"
                   "serial-number: \"%(serial_number)s\"\n"
                   "x-public-key-info: \"%(public_key_info)s\"\n" %
                   dict(label=label,
                        subject=subject,
                        issuer=issuer,
                        serial_number=serial_number,
                        public_key_info=public_key_info))
            if trusted is True:
                obj += "trusted: true\n"
            elif trusted is False:
                obj += "x-distrusted: true\n"
            obj += "{pem}\n\n".format(
                pem=cert.public_bytes(x509.Encoding.PEM).decode('ascii'))
            f.write(obj)

            if (cert.extended_key_usage is not None and
                    public_key_info not in has_eku):
                try:
                    ext_key_usage = cert.extended_key_usage_bytes
                except PyAsn1Error as e:
                    root_logger.warning(
                        "Failed to encode extended key usage for \"%s\": %s",
                        nickname, e)
                    continue
                value = urllib.parse.quote(ext_key_usage)
                obj = ("[p11-kit-object-v1]\n"
                       "class: x-certificate-extension\n"
                       "label: \"ExtendedKeyUsage for %(label)s\"\n"
                       "x-public-key-info: \"%(public_key_info)s\"\n"
                       "object-id: 2.5.29.37\n"
                       "value: \"%(value)s\"\n\n" %
                       dict(label=label,
                            public_key_info=public_key_info,
                            value=value))
                f.write(obj)
                has_eku.add(public_key_info)

        f.close()

        # Add the CA to the systemwide CA trust database
        if not self.reload_systemwide_ca_store():
            return False

        return True

    # Credits to upstream developer
    def remove_ca_certs_from_systemwide_ca_store(self):
        result = True
        update = False

        # Remove CA cert from systemwide store
        for new_cacert_path in (paths.IPA_P11_KIT,
                                paths.SYSTEMWIDE_IPA_CA_CRT):
            if not os.path.exists(new_cacert_path):
                continue
            try:
                os.remove(new_cacert_path)
            except OSError as e:
                root_logger.error(
                    "Could not remove %s: %s", new_cacert_path, e)
                result = False
            else:
                update = True

        if update:
            if not self.reload_systemwide_ca_store():
                return False

        return result

    # Credits to upstream developer
    def backup_and_replace_hostname(self, fstore, statestore, hostname):
        old_hostname = socket.gethostname()
        try:
            ipautil.run([paths.BIN_HOSTNAME, hostname])
        except ipautil.CalledProcessError as e:
            print >>sys.stderr, ("Failed to set this machine hostname to "
                                 "%s (%s)." % (hostname, str(e)))

        filepath = paths.ETC_HOSTNAME
        if os.path.exists(filepath):
            # read old hostname
            with open(filepath, 'r') as f:
                for line in f.readlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        # skip comment or empty line
                        continue
                    old_hostname = line
                    break
            fstore.backup_file(filepath)

        with open(filepath, 'w') as f:
            f.write("%s\n" % hostname)
        os.chmod(filepath,
                 stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        os.chown(filepath, 0, 0)
        self.restore_context(filepath)

        # store old hostname
        statestore.backup_state('network', 'hostname', old_hostname)

    # Credits to upstream developer
    def restore_network_configuration(self, fstore, statestore):
        old_filepath = paths.SYSCONFIG_NETWORK
        old_hostname = statestore.get_state('network', 'hostname')
        hostname_was_configured = False

        if fstore.has_file(old_filepath):
            # This is Fedora >=18 instance that was upgraded from previous
            # Fedora version which held network configuration
            # in /etc/sysconfig/network
            old_filepath_restore = paths.SYSCONFIG_NETWORK_IPABKP
            fstore.restore_file(old_filepath, old_filepath_restore)
            print("Deprecated configuration file '%s' was restored to '%s'" \
                    % (old_filepath, old_filepath_restore))
            hostname_was_configured = True

        filepath = paths.ETC_HOSTNAME
        if fstore.has_file(filepath):
            fstore.restore_file(filepath)
            hostname_was_configured = True

        if not hostname_was_configured and old_hostname:
            # hostname was not configured before but was set by IPA. Delete
            # /etc/hostname to restore previous configuration
            try:
                os.remove(filepath)
            except OSError:
                pass

    def set_selinux_booleans(self, required_settings, backup_func=None):
        return False # FIXME?

    # Credits to upstream developer
    def create_system_user(self, name, group, homedir, shell, uid = None, gid = None, comment = None):
        if name == 'pkiuser':
            if uid is None:
                uid = 29
            if gid is None:
                gid = 29
            if comment is None:
                comment = 'CA System User'
        if name == 'dirsrv':
            if comment is None:
                comment = 'DS System User'

        super().create_system_user(name, group,
            homedir, shell, uid, gid, comment)


tasks = SuseTaskNamespace()

