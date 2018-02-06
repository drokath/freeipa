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
import time
import xml.dom.minidom

from ipaplatform.tasks import tasks
from ipaplatform.base import services as base_services
from ipapython import ipautil, dogtag
from ipapython.ipa_log_manager import root_logger
from ipalib import api
from ipaplatform.paths import paths

suse_system_units = dict((x, "%s.service" % x) for x in base_services.wellknownservices)
suse_system_units['httpd'] = 'apache2.service'
suse_system_units['messagebus'] = 'dbus.service'

suse_system_units['dirsrv'] = 'dirsrv@.service'
suse_system_units['pkids'] = 'dirsrv@PKI-IPA.service'
suse_system_units['pki-cad'] = 'pki-cad@pki-ca.service'
suse_system_units['pki_cad'] = suse_system_units['pki-cad']
suse_system_units['pki-tomcatd'] = 'pki-tomcatd@pki-tomcat.service'
suse_system_units['pki_tomcatd'] = suse_system_units['pki-tomcatd']
suse_system_units['ipa-otpd'] = 'ipa-otpd.socket'
suse_system_units['ipa-dnskeysyncd'] = 'ipa-dnskeysyncd.service'
suse_system_units['named-regular'] = 'named.service'
suse_system_units['named-pkcs11'] = 'named.service'
suse_system_units['named'] = 'named.service'
suse_system_units['ods-enforcerd'] = 'ods-enforcerd.service'
suse_system_units['ods_enforcerd'] = suse_system_units['ods-enforcerd']
suse_system_units['ods-signerd'] = 'ods-signerd.service'
suse_system_units['ods_signerd'] = suse_system_units['ods-signerd']


class SuseService(base_services.SystemdService):
    system_units = suse_system_units

    def __init__(self, service_name, api=None):
        systemd_name = service_name
        if service_name in self.system_units:
            systemd_name = self.system_units[service_name]
        else:
            if '.' not in service_name:
                systemd_name = "%s.service" % (service_name)
        super().__init__(service_name, systemd_name, api)


class SuseDirectoryService(SuseService):
    def tune_nofile_platform(self, num=8192, fstore=None):
        pass

    # Credits to upstream developer
    def restart(self, instance_name="", capture_output=True, wait=True):
        if instance_name:
            elements = self.systemd_name.split("@")

            srv_etc = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.systemd_name)
            srv_tgt = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt,
                                   self.service_instance(instance_name))

            if not os.path.exists(srv_etc):
                self.enable(instance_name)
            elif not os.path.samefile(srv_etc, srv_lnk):
                os.unlink(srv_lnk)
                os.symlink(srv_etc, srv_lnk)

        super().restart(instance_name,
            capture_output=capture_output, wait=wait)


class SuseIPAService(SuseService):
    # Credits to upstream developer
    def enable(self, instance_name=""):
        super().enable(instance_name)
        self.restart(instance_name)


class SuseSSHService(SuseService):
    def get_config_dir(self, instance_name=""):
        return '/etc/ssh'


class SuseCAService(SuseService):
    # Credits to upstream developer
    def wait_until_running(self):
        use_proxy = True
        if not (os.path.exists('/etc/apache2/conf.d/ipa.conf') and
                os.path.exists(paths.HTTPD_IPA_PKI_PROXY_CONF)):
            root_logger.debug(
                'The httpd proxy is not installed, wait on local port')
            use_proxy = False
        root_logger.debug('Waiting until the CA is running')
        timeout = float(api.env.startup_timeout)
        op_timeout = time.time() + timeout
        while time.time() < op_timeout:
            try:
                # FIXME https://fedorahosted.org/freeipa/ticket/4716
                # workaround
                #
                # status = dogtag.ca_status(use_proxy=use_proxy)
                #
                port = 8443
                if use_proxy:
                    port = 443

                url = "https://%(host_port)s%(path)s" % {
                    "host_port": ipautil.format_netloc(api.env.ca_host, port),
                    "path": "/ca/admin/ca/getStatus"
                }

                args = [
                    paths.BIN_WGET,
                    '-S', '-O', '-',
                    '--timeout=30',
                    '--no-check-certificate',
                    url
                ]

                stdout, stderr, returncode = ipautil.run(args)

                status = dogtag._parse_ca_status(stdout)
                # end of workaround
            except Exception as e:
                status = 'check interrupted due to error: %s' % e
            root_logger.debug('The CA status is: %s' % status)
            if status == 'running':
                break
            root_logger.debug('Waiting for CA to start...')
            time.sleep(1)
        else:
            raise RuntimeError('CA did not start in %ss' % timeout)

    # Credits to upstream developer
    def start(self, instance_name="", capture_output=True, wait=True):
        super().start(
            instance_name, capture_output=capture_output, wait=wait)
        if wait:
            self.wait_until_running()

    # Credits to upstream developer
    def restart(self, instance_name="", capture_output=True, wait=True):
        super().restart(
            instance_name, capture_output=capture_output, wait=wait)
        if wait:
            self.wait_until_running()


class SuseNamedService(SuseService):
    def get_user_name(self):
        return u'named'

    def get_group_name(self):
        return u'named'

    def get_binary_path(self):
        return paths.NAMED_PKCS11 # identical to the ordinary named

    def get_package_name(self):
        return u"bind" # identical to the ordinary named


class SuseODSEnforcerdService(SuseService):
    def get_user_name(self):
        return u'ods'

    def get_group_name(self):
        return u'ods'


# There is not a certmonger on SUSE, therefore everything is noop.
class SuseCertmongerService(base_services.PlatformService):
    def __init__(self, api=None):
        base_services.PlatformService.__init__(self, 'there-is-no-certmonger', api)

    def start(instance_name="", capture_output=True, wait=True, update_service_list=True):
        pass

    def stop(self, instance_name="", capture_output=True, update_service_list=True):
        pass


def suse_service_class_factory(name, api):
    if name == 'dirsrv':
        return SuseDirectoryService(name, api)
    if name == 'ipa':
        return SuseIPAService(name, api)
    if name == 'sshd':
        return SuseSSHService(name, api)
    if name in ('pki-cad', 'pki_cad', 'pki-tomcatd', 'pki_tomcatd'):
        return SuseCAService(name, api)
    if name == 'named':
        return SuseNamedService(name, api)
    if name in ('ods-enforcerd', 'ods_enforcerd'):
        return SuseODSEnforcerdService(name, api)
    if name == 'certmonger':
        return SuseCertmongerService(api)
    return SuseService(name, api)


class SuseServices(base_services.KnownServices):
    def service_class_factory(self, name, api):
        return suse_service_class_factory(name, api)

    # Credits to upstream developer
    def __init__(self):
        import ipalib
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = self.service_class_factory(s, ipalib.api)
        super().__init__(services)


timedate_services = ['ntpd']
service = suse_service_class_factory
knownservices = SuseServices()
