# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import
from __future__ import print_function

import errno
import logging
import socket
import getpass
import gssapi
import io
import ldif
import os
import re
import fileinput
import sys
import tempfile
import shutil
import stat  # pylint: disable=bad-python3-import
import traceback
import textwrap
from contextlib import contextmanager

from dns import resolver, rdatatype
from dns.exception import DNSException
import ldap
import ldapurl
import six
# pylint: disable=import-error
if six.PY3:
    # The SafeConfigParser class has been renamed to ConfigParser in Py3
    from configparser import ConfigParser as SafeConfigParser
else:
    from ConfigParser import SafeConfigParser
from six.moves.configparser import NoOptionError
# pylint: enable=import-error

from ipalib.install import sysrestore
from ipalib.install.kinit import kinit_password
import ipaplatform
from ipapython import ipautil, admintool, version
from ipapython.admintool import ScriptError
from ipapython.certdb import EXTERNAL_CA_TRUST_FLAGS
from ipapython.ipaldap import DIRMAN_DN, LDAPClient
from ipalib.util import validate_hostname
from ipalib import api, errors, x509
from ipapython.dn import DN
from ipaserver.install import certs, service, sysupgrade
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

# Used to determine install status
IPA_MODULES = [
    'httpd', 'kadmin', 'dirsrv', 'pki-tomcatd', 'install', 'krb5kdc', 'ntpd',
    'named']


class BadHostError(Exception):
    pass

class HostLookupError(BadHostError):
    pass

class HostForwardLookupError(HostLookupError):
    pass

class HostReverseLookupError(HostLookupError):
    pass

class HostnameLocalhost(HostLookupError):
    pass


class UpgradeVersionError(Exception):
    pass


class UpgradePlatformError(UpgradeVersionError):
    pass


class UpgradeDataOlderVersionError(UpgradeVersionError):
    pass


class UpgradeDataNewerVersionError(UpgradeVersionError):
    pass


class UpgradeMissingVersionError(UpgradeVersionError):
    pass


class ReplicaConfig(object):
    def __init__(self, top_dir=None):
        self.realm_name = ""
        self.domain_name = ""
        self.master_host_name = ""
        self.dirman_password = ""
        self.host_name = ""
        self.dir = ""
        self.subject_base = None
        self.setup_ca = False
        self.version = 0
        self.top_dir = top_dir

    subject_base = ipautil.dn_attribute_property('_subject_base')

def get_fqdn():
    fqdn = ""
    try:
        fqdn = socket.getfqdn()
    except Exception:
        try:
            fqdn = socket.gethostname()
        except Exception:
            fqdn = ""
    return fqdn

def verify_fqdn(host_name, no_host_dns=False, local_hostname=True):
    """
    Run fqdn checks for given host:
        - test hostname format
        - test that hostname is fully qualified
        - test forward and reverse hostname DNS lookup

    Raises `BadHostError` or derived Exceptions if there is an error

    :param host_name: The host name to verify.
    :param no_host_dns: If true, skip DNS resolution tests of the host name.
    :param local_hostname: If true, run additional checks for local hostnames
    """
    if len(host_name.split(".")) < 2 or host_name == "localhost.localdomain":
        raise BadHostError("Invalid hostname '%s', must be fully-qualified." % host_name)

    if host_name != host_name.lower():
        raise BadHostError("Invalid hostname '%s', must be lower-case." % host_name)

    if ipautil.valid_ip(host_name):
        raise BadHostError("IP address not allowed as a hostname")

    try:
        # make sure that the host name meets the requirements in ipalib
        validate_hostname(host_name)
    except ValueError as e:
        raise BadHostError("Invalid hostname '%s', %s" % (host_name, unicode(e)))

    if local_hostname:
        try:
            logger.debug('Check if %s is a primary hostname for localhost',
                         host_name)
            ex_name = socket.gethostbyaddr(host_name)
            logger.debug('Primary hostname for localhost: %s', ex_name[0])
            if host_name != ex_name[0]:
                raise HostLookupError("The host name %s does not match the primary host name %s. "\
                        "Please check /etc/hosts or DNS name resolution" % (host_name, ex_name[0]))
        except socket.gaierror:
            pass
        except socket.error as e:
            logger.debug(
                'socket.gethostbyaddr() error: %d: %s',
                e.errno, e.strerror)  # pylint: disable=no-member

    if no_host_dns:
        print("Warning: skipping DNS resolution of host", host_name)
        return

    try:
        logger.debug('Search DNS for %s', host_name)
        hostaddr = socket.getaddrinfo(host_name, None)
    except Exception as e:
        logger.debug('Search failed: %s', e)
        raise HostForwardLookupError("Unable to resolve host name, check /etc/hosts or DNS name resolution")

    if len(hostaddr) == 0:
        raise HostForwardLookupError("Unable to resolve host name, check /etc/hosts or DNS name resolution")

    # Verify this is NOT a CNAME
    try:
        logger.debug('Check if %s is not a CNAME', host_name)
        resolver.query(host_name, rdatatype.CNAME)
        raise HostReverseLookupError("The IPA Server Hostname cannot be a CNAME, only A and AAAA names are allowed.")
    except DNSException:
        pass

    # list of verified addresses to prevent multiple searches for the same address
    verified = set()
    for a in hostaddr:
        address = a[4][0]
        if address in verified:
            continue
        if address == '127.0.0.1' or address == '::1':
            raise HostForwardLookupError("The IPA Server hostname must not resolve to localhost (%s). A routable IP address must be used. Check /etc/hosts to see if %s is an alias for %s" % (address, host_name, address))
        try:
            logger.debug('Check reverse address of %s', address)
            revname = socket.gethostbyaddr(address)[0]
        except Exception as e:
            logger.debug('Check failed: %s', e)
            logger.error(
                "Unable to resolve the IP address %s to a host name, "
                "check /etc/hosts and DNS name resolution", address)
        else:
            logger.debug('Found reverse name: %s', revname)
            if revname != host_name:
                logger.error(
                    "The host name %s does not match the value %s obtained "
                    "by reverse lookup on IP address %s", host_name, revname,
                    address)
        verified.add(address)


def record_in_hosts(ip, host_name=None, conf_file=paths.HOSTS):
    """
    Search record in /etc/hosts - static table lookup for hostnames

    In case of match, returns a tuple of ip address and a list of
    hostname aliases
    When no record is matched, None is returned

    :param ip: IP address
    :param host_name: Optional hostname to search
    :param conf_file: Optional path to the lookup table
    """
    hosts = open(conf_file, 'r').readlines()
    for line in hosts:
        line = line.rstrip('\n')
        fields = line.partition('#')[0].split()
        if len(fields) == 0:
            continue

        try:
            hosts_ip = fields[0]
            names = fields[1:]

            if hosts_ip != ip:
                continue
            if host_name is not None:
                if host_name in names:
                    return (hosts_ip, names)
                else:
                    return None
            return (hosts_ip, names)
        except IndexError:
            print("Warning: Erroneous line '%s' in %s" % (line, conf_file))
            continue

    return None

def add_record_to_hosts(ip, host_name, conf_file=paths.HOSTS):
    hosts_fd = open(conf_file, 'r+')
    hosts_fd.seek(0, 2)
    hosts_fd.write(ip+'\t'+host_name+' '+host_name.split('.')[0]+'\n')
    hosts_fd.close()


def read_ip_addresses():
    ips = []
    msg_first = "Please provide the IP address to be used for this host name"
    msg_other = "Enter an additional IP address, or press Enter to skip"
    while True:
        msg = msg_other if ips else msg_first
        ip = ipautil.user_input(msg, allow_empty=True)
        if not ip:
            break
        try:
            ip_parsed = ipautil.CheckedIPAddress(ip)
        except Exception as e:
            print("Error: Invalid IP Address %s: %s" % (ip, e))
            continue
        ips.append(ip_parsed)

    return ips


def read_dns_forwarders():
    addrs = []
    if ipautil.user_input("Do you want to configure DNS forwarders?", True):
        print("Following DNS servers are configured in /etc/resolv.conf: %s" %
                ", ".join(resolver.get_default_resolver().nameservers))
        if ipautil.user_input("Do you want to configure these servers as DNS "
                "forwarders?", True):
            addrs = resolver.default_resolver.nameservers[:]
            print("All DNS servers from /etc/resolv.conf were added. You can "
                  "enter additional addresses now:")
        while True:
            ip = ipautil.user_input("Enter an IP address for a DNS forwarder, "
                                    "or press Enter to skip", allow_empty=True)
            if not ip:
                break
            try:
                ip_parsed = ipautil.CheckedIPAddress(ip, parse_netmask=False)
            except Exception as e:
                print("Error: Invalid IP Address %s: %s" % (ip, e))
                print("DNS forwarder %s not added." % ip)
                continue

            print("DNS forwarder %s added. You may add another." % ip)
            addrs.append(str(ip_parsed))

    if not addrs:
        print("No DNS forwarders configured")

    return addrs

def get_password(prompt):
    if os.isatty(sys.stdin.fileno()):
        return getpass.getpass(prompt)
    else:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
        if not line:
            raise EOFError()
        return line.rstrip()


def _read_password_default_validator(password):
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")


def validate_dm_password_ldap(password):
    """
    Validate DM password by attempting to connect to LDAP. api.env has to
    contain valid ldap_uri.
    """
    client = LDAPClient(api.env.ldap_uri, cacert=paths.IPA_CA_CRT)
    try:
        client.simple_bind(DIRMAN_DN, password)
    except errors.ACIError:
        raise ValueError("Invalid Directory Manager password")
    else:
        client.unbind()


def read_password(user, confirm=True, validate=True, retry=True, validator=_read_password_default_validator):
    correct = False
    pwd = None
    try:
        while not correct:
            if not retry:
                correct = True
            pwd = get_password(user + " password: ")
            if not pwd:
                continue
            if validate:
                try:
                    validator(pwd)
                except ValueError as e:
                    print(str(e))
                    pwd = None
                    continue
            if not confirm:
                correct = True
                continue
            pwd_confirm = get_password("Password (confirm): ")
            if pwd != pwd_confirm:
                print("Password mismatch!")
                print("")
                pwd = None
            else:
                correct = True
    except EOFError:
        return None
    finally:
        print("")
    return pwd

def update_file(filename, orig, subst):
    if os.path.exists(filename):
        st = os.stat(filename)
        pattern = "%s" % re.escape(orig)
        p = re.compile(pattern)
        for line in fileinput.input(filename, inplace=1):
            if not p.search(line):
                sys.stdout.write(line)
            else:
                sys.stdout.write(p.sub(subst, line))
        fileinput.close()
        os.chown(filename, st.st_uid, st.st_gid) # reset perms
        return 0
    else:
        print("File %s doesn't exist." % filename)
        return 1


def quote_directive_value(value, quote_char):
    """Quote a directive value
    :param value: string to quote
    :param quote_char: character which is used for quoting. All prior
        occurences will be escaped before quoting to avoid unparseable value.
    :returns: processed value
    """
    if value.startswith(quote_char) and value.endswith(quote_char):
        return value

    return "{quote}{value}{quote}".format(
        quote=quote_char,
        value="".join(ipautil.escape_seq(quote_char, value))
    )


def unquote_directive_value(value, quote_char):
    """Unquote a directive value
    :param value: string to unquote
    :param quote_char: character to strip. All escaped occurences of
        `quote_char` will be uncescaped during processing
    :returns: processed value
    """
    unescaped_value = "".join(ipautil.unescape_seq(quote_char, value))
    if (unescaped_value.startswith(quote_char) and
            unescaped_value.endswith(quote_char)):
        return unescaped_value[1:-1]

    return unescaped_value


_SENTINEL = object()


class DirectiveSetter(object):
    """Safe directive setter

    with DirectiveSetter('/path/to/conf') as ds:
        ds.set(key, value)
    """
    def __init__(self, filename, quotes=True, separator=' '):
        self.filename = os.path.abspath(filename)
        self.quotes = quotes
        self.separator = separator
        self.lines = None
        self.stat = None

    def __enter__(self):
        with io.open(self.filename) as f:
            self.stat = os.fstat(f.fileno())
            self.lines = list(f)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # something went wrong, reset
            self.lines = None
            self.stat = None
            return

        directory, prefix = os.path.split(self.filename)
        # use tempfile in same directory to have atomic rename
        fd, name = tempfile.mkstemp(prefix=prefix, dir=directory, text=True)
        with io.open(fd, mode='w', closefd=True) as f:
            for line in self.lines:
                if not isinstance(line, six.text_type):
                    line = line.decode('utf-8')
                f.write(line)
            self.lines = None
            os.fchmod(f.fileno(), stat.S_IMODE(self.stat.st_mode))
            os.fchown(f.fileno(), self.stat.st_uid, self.stat.st_gid)
            self.stat = None
            # flush and sync tempfile inode
            f.flush()
            os.fsync(f.fileno())

        # rename file and sync directory inode
        os.rename(name, self.filename)
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)

    def set(self, directive, value, quotes=_SENTINEL, separator=_SENTINEL):
        """Set a single directive
        """
        if quotes is _SENTINEL:
            quotes = self.quotes
        if separator is _SENTINEL:
            separator = self.separator
        # materialize lines
        # set_directive_lines() modify item, shrink or enlage line count
        self.lines = list(set_directive_lines(
            quotes, separator, directive, value, self.lines
        ))

    def setitems(self, items):
        """Set multiple directives from a dict or list with key/value pairs
        """
        if isinstance(items, dict):
            # dict-like, use sorted for stable order
            items = sorted(items.items())
        for k, v in items:
            self.set(k, v)


def set_directive(filename, directive, value, quotes=True, separator=' '):
    """Set a name/value pair directive in a configuration file.

    A value of None means to drop the directive.

    Does not tolerate (or put) spaces around the separator.

    :param filename: input filename
    :param directive: directive name
    :param value: value of the directive
    :param quotes: whether to quote `value` in double quotes. If true, then
        any existing double quotes are first escaped to avoid
        unparseable directives.
    :param separator: character serving as separator between directive and
        value.  Correct value required even when dropping a directive.
    """
    st = os.stat(filename)
    with open(filename, 'r') as f:
        lines = list(f)  # read the whole file
        # materialize new list
        new_lines = list(set_directive_lines(
            quotes, separator, directive, value, lines
        ))
    with open(filename, 'w') as f:
        # don't construct the whole string; write line-wise
        for line in new_lines:
            f.write(line)
    os.chown(filename, st.st_uid, st.st_gid)  # reset perms


def set_directive_lines(quotes, separator, k, v, lines):
    """Set a name/value pair in a configuration (iterable of lines).

    Replaces the value of the key if found, otherwise adds it at
    end.  If value is ``None``, remove the key if found.

    Takes an iterable of lines (with trailing newline).
    Yields lines (with trailing newline).

    """
    new_line = ""
    if v is not None:
        v_quoted = quote_directive_value(v, '"') if quotes else v
        new_line = ''.join([k, separator, v_quoted, '\n'])

    found = False
    matcher = re.compile(r'\s*{}'.format(re.escape(k + separator)))
    for line in lines:
        if matcher.match(line):
            found = True
            if v is not None:
                yield new_line
        else:
            yield line

    if not found and v is not None:
        yield new_line


def get_directive(filename, directive, separator=' '):
    """
    A rather inefficient way to get a configuration directive.

    :param filename: input filename
    :param directive: directive name
    :param separator: separator between directive and value

    :returns: The (unquoted) value if the directive was found, None otherwise
    """
    fd = open(filename, "r")
    for line in fd:
        if line.lstrip().startswith(directive):
            line = line.strip()

            (directive, sep, value) = line.partition(separator)
            if not sep or not value:
                raise ValueError("Malformed directive: {}".format(line))

            result = unquote_directive_value(value.strip(), '"')
            result = result.strip(' ')
            fd.close()
            return result
    fd.close()
    return None

def kadmin(command):
    return ipautil.run(["kadmin.local", "-q", command,
                        "-x", "ipa-setup-override-restrictions"],
                       capture_output=True,
                       capture_error=True)


def kadmin_addprinc(principal):
    return kadmin("addprinc -randkey " + principal)

def kadmin_modprinc(principal, options):
    return kadmin("modprinc " + options + " " + principal)

def create_keytab(path, principal):
    try:
        if os.path.isfile(path):
            os.remove(path)
    except os.error:
        logger.critical("Failed to remove %s.", path)

    return kadmin("ktadd -k " + path + " " + principal)

def resolve_ip_addresses_nss(fqdn):
    """Get list of IP addresses for given host (using NSS/getaddrinfo).
    :returns:
        list of IP addresses as UnsafeIPAddress objects
    """
    # it would be good disable search list processing from resolv.conf
    # to avoid cases where we get IP address for an totally different name
    # but there is no way to do this using getaddrinfo parameters
    try:
        addrinfos = socket.getaddrinfo(fqdn, None,
                                       socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.error as ex:
        if ex.errno == socket.EAI_NODATA or ex.errno == socket.EAI_NONAME:
            logger.debug('Name %s does not have any address: %s', fqdn, ex)
            return set()
        else:
            raise

    # accept whatever we got from NSS
    ip_addresses = set()
    for ai in addrinfos:
        try:
            ip = ipautil.UnsafeIPAddress(ai[4][0])
        except ValueError as ex:
            # getaddinfo may return link-local address other similar oddities
            # which are not accepted by CheckedIPAddress - skip these
            logger.warning('Name %s resolved to an unacceptable IP '
                           'address %s: %s', fqdn, ai[4][0], ex)
        else:
            ip_addresses.add(ip)
    logger.debug('Name %s resolved to %s', fqdn, ip_addresses)
    return ip_addresses

def get_host_name(no_host_dns):
    """
    Get the current FQDN from the socket and verify that it is valid.

    no_host_dns is a boolean that determines whether we enforce that the
    hostname is resolvable.

    Will raise a RuntimeError on error, returns hostname on success
    """
    hostname = get_fqdn()
    verify_fqdn(hostname, no_host_dns)
    return hostname

def get_server_ip_address(host_name, unattended, setup_dns, ip_addresses):
    hostaddr = resolve_ip_addresses_nss(host_name)
    if hostaddr.intersection(
            {ipautil.UnsafeIPAddress(ip) for ip in ['127.0.0.1', '::1']}):
        print("The hostname resolves to the localhost address (127.0.0.1/::1)", file=sys.stderr)
        print("Please change your /etc/hosts file so that the hostname", file=sys.stderr)
        print("resolves to the ip address of your network interface.", file=sys.stderr)
        print("The KDC service does not listen on localhost", file=sys.stderr)
        print("", file=sys.stderr)
        print("Please fix your /etc/hosts file and restart the setup program", file=sys.stderr)
        raise ScriptError()

    ips = []
    if len(hostaddr):
        for ha in hostaddr:
            try:
                ips.append(ipautil.CheckedIPAddress(ha))
            except ValueError as e:
                logger.warning("Invalid IP address %s for %s: %s",
                               ha, host_name, unicode(e))

    if not ips and not ip_addresses:
        if not unattended:
            ip_addresses = read_ip_addresses()

    if ip_addresses:
        if setup_dns:
            ips = ip_addresses
        else:
            # all specified addresses was resolved for this host
            if set(ip_addresses) <= set(ips):
                ips = ip_addresses
            else:
                print("Error: the hostname resolves to IP address(es) that are different", file=sys.stderr)
                print("from those provided on the command line.  Please fix your DNS", file=sys.stderr)
                print("or /etc/hosts file and restart the installation.", file=sys.stderr)
                print("Provided but not resolved address(es): %s" % \
                                    ", ".join(str(ip) for ip in (set(ip_addresses) - set(ips))), file=sys.stderr)
                raise ScriptError()

    if not ips:
        print("No usable IP address provided nor resolved.", file=sys.stderr)
        raise ScriptError()

    for ip_address in ips:
        # check /etc/hosts sanity
        hosts_record = record_in_hosts(str(ip_address))

        if hosts_record is not None:
            primary_host = hosts_record[1][0]
            if primary_host != host_name:
                print("Error: there is already a record in /etc/hosts for IP address %s:" \
                        % ip_address, file=sys.stderr)
                print(hosts_record[0], " ".join(hosts_record[1]), file=sys.stderr)
                print("Chosen hostname %s does not match configured canonical hostname %s" \
                        % (host_name, primary_host), file=sys.stderr)
                print("Please fix your /etc/hosts file and restart the installation.", file=sys.stderr)
                raise ScriptError()

    return ips


def update_hosts_file(ip_addresses, host_name, fstore):
    """
    Update hosts with specified addresses
    :param ip_addresses: list of IP addresses
    :return:
    """
    if not fstore.has_file(paths.HOSTS):
        fstore.backup_file(paths.HOSTS)
    for ip_address in ip_addresses:
        if record_in_hosts(str(ip_address)):
            continue
        print("Adding [{address!s} {name}] to your /etc/hosts file".format(
            address=ip_address, name=host_name))
        add_record_to_hosts(str(ip_address), host_name)


def _ensure_nonempty_string(string, message):
    if not isinstance(string, str) or not string:
        raise ValueError(message)


# uses gpg to compress and encrypt a file
def encrypt_file(source, dest, password, workdir=None):
    _ensure_nonempty_string(source, 'Missing Source File')
    # stat it so that we get back an exception if it does no t exist
    os.stat(source)

    _ensure_nonempty_string(dest, 'Missing Destination File')
    _ensure_nonempty_string(password, 'Missing Password')

    # create a tempdir so that we can clean up with easily
    tempdir = tempfile.mkdtemp('', 'ipa-', workdir)
    gpgdir = os.path.join(tempdir, ".gnupg")

    try:
        try:
            # give gpg a fake dir so that we can leater remove all
            # the cruft when we clean up the tempdir
            os.mkdir(gpgdir)
            args = [paths.GPG_AGENT,
                    '--batch',
                    '--homedir', gpgdir,
                    '--daemon', paths.GPG,
                    '--batch',
                    '--homedir', gpgdir,
                    '--passphrase-fd', '0',
                    '--yes',
                    '--no-tty',
                    '-o', dest,
                    '-c', source]
            ipautil.run(args, password, skip_output=True)
        except:
            raise
    finally:
        # job done, clean up
        shutil.rmtree(tempdir, ignore_errors=True)


def decrypt_file(source, dest, password, workdir=None):
    _ensure_nonempty_string(source, 'Missing Source File')
    # stat it so that we get back an exception if it does no t exist
    os.stat(source)

    _ensure_nonempty_string(dest, 'Missing Destination File')
    _ensure_nonempty_string(password, 'Missing Password')

    # create a tempdir so that we can clean up with easily
    tempdir = tempfile.mkdtemp('', 'ipa-', workdir)
    gpgdir = os.path.join(tempdir, ".gnupg")

    try:
        try:
            # give gpg a fake dir so that we can leater remove all
            # the cruft when we clean up the tempdir
            os.mkdir(gpgdir)
            args = [paths.GPG_AGENT,
                    '--batch',
                    '--homedir', gpgdir,
                    '--daemon', paths.GPG,
                    '--batch',
                    '--homedir', gpgdir,
                    '--passphrase-fd', '0',
                    '--yes',
                    '--no-tty',
                    '-o', dest,
                    '-d', source]
            ipautil.run(args, password, skip_output=True)
        except:
            raise
    finally:
        # job done, clean up
        shutil.rmtree(tempdir, ignore_errors=True)


def expand_replica_info(filename, password):
    """
    Decrypt and expand a replica installation file into a temporary
    location. The caller is responsible to remove this directory.
    """
    top_dir = tempfile.mkdtemp("ipa")
    tarfile = top_dir+"/files.tar"
    dir_path = top_dir + "/realm_info"
    decrypt_file(filename, tarfile, password, top_dir)
    ipautil.run(["tar", "xf", tarfile, "-C", top_dir])
    os.remove(tarfile)

    return top_dir, dir_path

def read_replica_info(dir_path, rconfig):
    """
    Read the contents of a replica installation file.

    rconfig is a ReplicaConfig object
    """
    filename = os.path.join(dir_path, "realm_info")
    config = SafeConfigParser()
    config.read(filename)

    rconfig.realm_name = config.get("realm", "realm_name")
    rconfig.master_host_name = config.get("realm", "master_host_name")
    rconfig.domain_name = config.get("realm", "domain_name")
    rconfig.host_name = config.get("realm", "destination_host")
    rconfig.subject_base = config.get("realm", "subject_base")
    try:
        rconfig.version = int(config.get("realm", "version"))
    except NoOptionError:
        pass

def read_replica_info_dogtag_port(config_dir):
    portfile = config_dir + "/dogtag_directory_port.txt"
    default_port = 7389
    if not os.path.isfile(portfile):
        dogtag_master_ds_port = default_port
    else:
        with open(portfile) as fd:
            try:
                dogtag_master_ds_port = int(fd.read())
            except (ValueError, IOError) as e:
                logger.debug('Cannot parse dogtag DS port: %s', e)
                logger.debug('Default to %d', default_port)
                dogtag_master_ds_port = default_port

    return dogtag_master_ds_port


def create_replica_config(dirman_password, filename, options):
    top_dir = None
    try:
        top_dir, dir = expand_replica_info(filename, dirman_password)
    except Exception as e:
        logger.error("Failed to decrypt or open the replica file.")
        raise ScriptError(
            "ERROR: Failed to decrypt or open the replica file.\n"
            "Verify you entered the correct Directory Manager password.")
    config = ReplicaConfig(top_dir)
    read_replica_info(dir, config)
    logger.debug(
        'Installing replica file with version %d '
        '(0 means no version in prepared file).',
        config.version)
    if config.version and config.version > version.NUM_VERSION:
        logger.error(
            'A replica file from a newer release (%d) cannot be installed on '
            'an older version (%d)',
            config.version, version.NUM_VERSION)
        raise ScriptError()
    config.dirman_password = dirman_password
    try:
        host = get_host_name(options.no_host_dns)
    except BadHostError as e:
        logger.error("%s", str(e))
        raise ScriptError()
    if config.host_name != host:
        try:
            print("This replica was created for '%s' but this machine is named '%s'" % (config.host_name, host))
            if not ipautil.user_input("This may cause problems. Continue?", False):
                logger.debug(
                    "Replica was created for %s but machine is named %s  "
                    "User chose to exit",
                    config.host_name, host)
                sys.exit(0)
            config.host_name = host
            print("")
        except KeyboardInterrupt:
            logger.debug("Keyboard Interrupt")
            raise ScriptError(rval=0)
    config.dir = dir
    config.ca_ds_port = read_replica_info_dogtag_port(config.dir)
    return config


def check_server_configuration():
    """
    Check if IPA server is configured on the system.

    This is done by checking if there are system restore (uninstall) files
    present on the system. Note that this check can only be run with root
    privileges.

    When IPA is not configured, this function raises a RuntimeError exception.
    Most convenient use case for the function is in install tools that require
    configured IPA for its function.
    """
    server_fstore = sysrestore.FileStore(paths.SYSRESTORE)
    if not server_fstore.has_files():
        raise RuntimeError("IPA is not configured on this system.")


def remove_file(filename):
    """
    Remove a file and log any exceptions raised.
    """
    try:
        if os.path.lexists(filename):
            os.unlink(filename)
    except Exception as e:
        logger.error('Error removing %s: %s', filename, str(e))


def rmtree(path):
    """
    Remove a directory structure and log any exceptions raised.
    """
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
    except Exception as e:
        logger.error('Error removing %s: %s', path, str(e))


def is_ipa_configured():
    """
    Using the state and index install files determine if IPA is already
    configured.
    """
    installed = False

    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    for module in IPA_MODULES:
        if sstore.has_state(module):
            logger.debug('%s is configured', module)
            installed = True
        else:
            logger.debug('%s is not configured', module)

    if fstore.has_files():
        logger.debug('filestore has files')
        installed = True
    else:
        logger.debug('filestore is tracking no files')

    return installed


def run_script(main_function, operation_name, log_file_name=None,
        fail_message=None):
    """Run the given function as a command-line utility

    This function:

    - Runs the given function
    - Formats any errors
    - Exits with the appropriate code

    :param main_function: Function to call
    :param log_file_name: Name of the log file (displayed on unexpected errors)
    :param operation_name: Name of the script
    :param fail_message: Optional message displayed on failure
    """

    logger.info('Starting script: %s', operation_name)
    try:
        try:
            return_value = main_function()
        except BaseException as e:
            if (
                isinstance(e, SystemExit) and
                (e.code is None or e.code == 0)  # pylint: disable=no-member
            ):
                # Not an error after all
                logger.info('The %s command was successful', operation_name)
            else:
                # Log at the DEBUG level, which is not output to the console
                # (unless in debug/verbose mode), but is written to a logfile
                # if one is open.
                tb = sys.exc_info()[2]
                logger.debug("%s", '\n'.join(traceback.format_tb(tb)))
                logger.debug('The %s command failed, exception: %s: %s',
                             operation_name, type(e).__name__, e)
                if fail_message and not isinstance(e, SystemExit):
                    print(fail_message)
                raise
        else:
            if return_value:
                logger.info('The %s command failed, return value %s',
                            operation_name, return_value)
            else:
                logger.info('The %s command was successful', operation_name)
            sys.exit(return_value)

    except BaseException as error:
        message, exitcode = handle_error(error, log_file_name)
        if message:
            print(message, file=sys.stderr)
        sys.exit(exitcode)


def handle_error(error, log_file_name=None):
    """Handle specific errors. Returns a message and return code"""

    if isinstance(error, SystemExit):
        if isinstance(error.code, int):
            return None, error.code
        elif error.code is None:
            return None, 0
        else:
            return str(error), 1
    if isinstance(error, RuntimeError):
        return str(error), 1
    if isinstance(error, KeyboardInterrupt):
        return "Cancelled.", 1

    if isinstance(error, admintool.ScriptError):
        return error.msg, error.rval

    if isinstance(error, socket.error):
        return error, 1

    if isinstance(error, errors.ACIError):
        return str(error), 1
    if isinstance(error, ldap.INVALID_CREDENTIALS):
        return "Invalid password", 1
    if isinstance(error, ldap.INSUFFICIENT_ACCESS):
        return "Insufficient access", 1
    if isinstance(error, ldap.LOCAL_ERROR):
        return error.args[0].get('info', ''), 1
    if isinstance(error, ldap.SERVER_DOWN):
        return error.args[0]['desc'], 1
    if isinstance(error, ldap.LDAPError):
        message = 'LDAP error: %s\n%s\n%s' % (
            type(error).__name__,
            error.args[0]['desc'].strip(),
            error.args[0].get('info', '').strip()
        )
        return message, 1

    if isinstance(error, errors.LDAPError):
        return "An error occurred while performing operations: %s" % error, 1

    if isinstance(error, HostnameLocalhost):
        message = textwrap.dedent("""
            The hostname resolves to the localhost address (127.0.0.1/::1)
            Please change your /etc/hosts file so that the hostname
            resolves to the ip address of your network interface.

            Please fix your /etc/hosts file and restart the setup program
            """).strip()
        return message, 1

    if log_file_name:
        message = "Unexpected error - see %s for details:" % log_file_name
    else:
        message = "Unexpected error"
    message += '\n%s: %s' % (type(error).__name__, error)
    return message, 1


def load_pkcs12(cert_files, key_password, key_nickname, ca_cert_files,
                host_name=None, realm_name=None):
    """
    Load and verify server certificate and private key from multiple files

    The files are accepted in PEM and DER certificate, PKCS#7 certificate
    chain, PKCS#8 and raw private key and PKCS#12 formats.

    :param cert_files: Names of server certificate and private key files to
        import
    :param key_password: Password to decrypt private keys
    :param key_nickname: Nickname of the private key to import from PKCS#12
        files
    :param ca_cert_files: Names of CA certificate files to import
    :param host_name: Host name of the server
    :returns: Temporary PKCS#12 file with the server certificate, private key
        and CA certificate chain, password to unlock the PKCS#12 file and
        the CA certificate of the CA that issued the server certificate
    """
    with certs.NSSDatabase() as nssdb:
        nssdb.create_db()

        try:
            nssdb.import_files(cert_files, True, key_password, key_nickname)
        except RuntimeError as e:
            raise ScriptError(str(e))

        if ca_cert_files:
            try:
                nssdb.import_files(ca_cert_files)
            except RuntimeError as e:
                raise ScriptError(str(e))

        for nickname, trust_flags in nssdb.list_certs():
            if trust_flags.has_key:
                key_nickname = nickname
                continue
            nssdb.trust_root_cert(nickname, EXTERNAL_CA_TRUST_FLAGS)

        # Check we have the whole cert chain & the CA is in it
        trust_chain = list(reversed(nssdb.get_trust_chain(key_nickname)))
        ca_cert = None
        for nickname in trust_chain[1:]:
            cert = nssdb.get_cert(nickname)
            if ca_cert is None:
                ca_cert = cert

            subject = DN(cert.subject)
            issuer = DN(cert.issuer)

            if subject == issuer:
                break
        else:
            raise ScriptError(
                "The full certificate chain is not present in %s" %
                (", ".join(cert_files)))

        for nickname in trust_chain[1:]:
            try:
                nssdb.verify_ca_cert_validity(nickname)
            except ValueError as e:
                raise ScriptError(
                    "CA certificate %s in %s is not valid: %s" %
                    (subject, ", ".join(cert_files), e))

        if host_name is not None:
            try:
                nssdb.verify_server_cert_validity(key_nickname, host_name)
            except ValueError as e:
                raise ScriptError(
                    "The server certificate in %s is not valid: %s" %
                    (", ".join(cert_files), e))

        if realm_name is not None:
            try:
                nssdb.verify_kdc_cert_validity(key_nickname, realm_name)
            except ValueError as e:
                raise ScriptError(
                    "The KDC certificate in %s is not valid: %s" %
                    (", ".join(cert_files), e))

        out_file = tempfile.NamedTemporaryFile()
        out_password = ipautil.ipa_generate_password()
        out_pwdfile = ipautil.write_tmp_file(out_password)
        args = [
            paths.PK12UTIL,
            '-o', out_file.name,
            '-n', key_nickname,
            '-d', nssdb.secdir,
            '-k', nssdb.pwd_file,
            '-w', out_pwdfile.name,
        ]
        ipautil.run(args)

    return out_file, out_password, ca_cert


@contextmanager
def stopped_service(service, instance_name=""):
    """
    Ensure that the specified service is stopped while the commands within
    this context are executed.

    Service is started at the end of the execution.
    """

    if instance_name:
        log_instance_name = "@{instance}".format(instance=instance_name)
    else:
        log_instance_name = ""

    logger.debug('Ensuring that service %s%s is not running while '
                 'the next set of commands is being executed.', service,
                 log_instance_name)

    service_obj = services.service(service, api)

    # Figure out if the service is running, if not, yield
    if not service_obj.is_running(instance_name):
        logger.debug('Service %s%s is not running, continue.', service,
                     log_instance_name)
        yield
    else:
        # Stop the service, do the required stuff and start it again
        logger.debug('Stopping %s%s.', service, log_instance_name)
        service_obj.stop(instance_name)
        try:
            yield
        finally:
            logger.debug('Starting %s%s.', service, log_instance_name)
            service_obj.start(instance_name)


def check_entropy():
    """
    Checks if the system has enough entropy, if not, displays warning message
    """
    try:
        with open(paths.ENTROPY_AVAIL, 'r') as efname:
            if int(efname.read()) < 200:
                emsg = 'WARNING: Your system is running out of entropy, ' \
                        'you may experience long delays'
                service.print_msg(emsg)
                logger.debug("%s", emsg)
    except IOError as e:
        logger.debug(
            "Could not open %s: %s", paths.ENTROPY_AVAIL, e)
    except ValueError as e:
        logger.debug("Invalid value in %s %s", paths.ENTROPY_AVAIL, e)


def load_external_cert(files, ca_subject):
    """
    Load and verify external CA certificate chain from multiple files.

    The files are accepted in PEM and DER certificate and PKCS#7 certificate
    chain formats.

    :param files: Names of files to import
    :param ca_subject: IPA CA subject DN
    :returns: Temporary file with the IPA CA certificate and temporary file
        with the external CA certificate chain
    """
    with certs.NSSDatabase() as nssdb:
        nssdb.create_db()

        try:
            nssdb.import_files(files)
        except RuntimeError as e:
            raise ScriptError(str(e))

        ca_subject = DN(ca_subject)
        ca_nickname = None
        cache = {}
        for nickname, _trust_flags in nssdb.list_certs():
            cert = nssdb.get_cert(nickname)
            subject = DN(cert.subject)
            issuer = DN(cert.issuer)

            cache[nickname] = (cert, subject, issuer)
            if subject == ca_subject:
                ca_nickname = nickname
            nssdb.trust_root_cert(nickname, EXTERNAL_CA_TRUST_FLAGS)

        if ca_nickname is None:
            raise ScriptError(
                "IPA CA certificate with subject '%s' "
                "was not found in %s." % (ca_subject, (",".join(files))))

        trust_chain = list(reversed(nssdb.get_trust_chain(ca_nickname)))
        ca_cert_chain = []
        for nickname in trust_chain:
            cert, subject, issuer = cache[nickname]
            ca_cert_chain.append(cert)
            if subject == issuer:
                break
        else:
            raise ScriptError(
                "CA certificate chain in %s is incomplete: "
                "missing certificate with subject '%s'" %
                (", ".join(files), issuer))

        for nickname in trust_chain:
            try:
                nssdb.verify_ca_cert_validity(nickname)
            except ValueError as e:
                raise ScriptError(
                    "CA certificate %s in %s is not valid: %s" %
                    (subject, ", ".join(files), e))

    cert_file = tempfile.NamedTemporaryFile()
    cert_file.write(ca_cert_chain[0].public_bytes(x509.Encoding.PEM) + b'\n')
    cert_file.flush()

    ca_file = tempfile.NamedTemporaryFile()
    x509.write_certificate_list(ca_cert_chain[1:], ca_file.name)
    ca_file.flush()

    return cert_file, ca_file


def store_version():
    """Store current data version and platform. This is required for check if
    upgrade is required.
    """
    sysupgrade.set_upgrade_state('ipa', 'data_version',
                                 version.VENDOR_VERSION)
    sysupgrade.set_upgrade_state('ipa', 'platform', ipaplatform.NAME)


def check_version():
    """
    :raise UpgradePlatformError: if platform is not the same
    :raise UpgradeDataOlderVersionError: if data needs to be upgraded
    :raise UpgradeDataNewerVersionError: older version of IPA was detected than data
    :raise UpgradeMissingVersionError: if platform or version is missing
    """
    platform = sysupgrade.get_upgrade_state('ipa', 'platform')
    if platform is not None:
        if platform != ipaplatform.NAME:
            raise UpgradePlatformError(
                "platform mismatch (expected '%s', current '%s')" % (
                platform, ipaplatform.NAME)
            )
    else:
        raise UpgradeMissingVersionError("no platform stored")

    data_version = sysupgrade.get_upgrade_state('ipa', 'data_version')
    if data_version is not None:
        parsed_data_ver = tasks.parse_ipa_version(data_version)
        parsed_ipa_ver = tasks.parse_ipa_version(version.VENDOR_VERSION)
        if parsed_data_ver < parsed_ipa_ver:
            raise UpgradeDataOlderVersionError(
                "data needs to be upgraded (expected version '%s', current "
                "version '%s')" % (version.VENDOR_VERSION, data_version)
            )
        elif parsed_data_ver > parsed_ipa_ver:
            raise UpgradeDataNewerVersionError(
                "data are in newer version than IPA (data version '%s', IPA "
                "version '%s')" % (data_version, version.VENDOR_VERSION)
            )
    else:
        raise UpgradeMissingVersionError("no data_version stored")

def realm_to_serverid(realm_name):
    return "-".join(realm_name.split("."))


def realm_to_ldapi_uri(realm_name):
    serverid = realm_to_serverid(realm_name)
    socketname = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % (serverid,)
    return 'ldapi://' + ldapurl.ldapUrlEscape(socketname)


def check_creds(options, realm_name):

    # Check if ccache is available
    default_cred = None
    try:
        logger.debug('KRB5CCNAME set to %s',
                     os.environ.get('KRB5CCNAME', None))
        # get default creds, will raise if none found
        default_cred = gssapi.creds.Credentials()
        principal = str(default_cred.name)
    except gssapi.raw.misc.GSSError as e:
        logger.debug('Failed to find default ccache: %s', e)
        principal = None

    # Check if the principal matches the requested one (if any)
    if principal is not None and options.principal is not None:
        op = options.principal
        if op.find('@') == -1:
            op = '%s@%s' % (op, realm_name)
        if principal != op:
            logger.debug('Specified principal %s does not match '
                         'available credentials (%s)',
                         options.principal, principal)
            principal = None

    if principal is None:
        (ccache_fd, ccache_name) = tempfile.mkstemp()
        os.close(ccache_fd)
        options.created_ccache_file = ccache_name

        if options.principal is not None:
            principal = options.principal
        else:
            principal = 'admin'
        stdin = None
        if principal.find('@') == -1:
            principal = '%s@%s' % (principal, realm_name)
        if options.admin_password is not None:
            stdin = options.admin_password
        else:
            if not options.unattended:
                try:
                    stdin = getpass.getpass("Password for %s: " % principal)
                except EOFError:
                    stdin = None
                if not stdin:
                    logger.error(
                        "Password must be provided for %s.", principal)
                    raise ScriptError("Missing password for %s" % principal)
            else:
                if sys.stdin.isatty():
                    logger.error("Password must be provided in "
                                 "non-interactive mode.")
                    logger.info("This can be done via "
                                "echo password | ipa-client-install "
                                "... or with the -w option.")
                    raise ScriptError("Missing password for %s" % principal)
                else:
                    stdin = sys.stdin.readline()

            # set options.admin_password for future use
            options.admin_password = stdin

        try:
            kinit_password(principal, stdin, ccache_name)
        except RuntimeError as e:
            logger.error("Kerberos authentication failed: %s", e)
            raise ScriptError("Invalid credentials: %s" % e)

        os.environ['KRB5CCNAME'] = ccache_name


class ModifyLDIF(ldif.LDIFParser):
    """
    Allows to modify LDIF file.

    Operations keep the order in which were specified per DN.
    Warning: only modifications of existing DNs are supported
    """
    def __init__(self, input_file, output_file):
        """
        :param input_file: an LDIF
        :param output_file: an LDIF file
        """
        ldif.LDIFParser.__init__(self, input_file)
        self.writer = ldif.LDIFWriter(output_file)
        self.dn_updated = set()

        self.modifications = {}  # keep modify operations in original order

    def add_value(self, dn, attr, values):
        """
        Add value to LDIF.
        :param dn: DN of entry (must exists)
        :param attr: attribute name
        :param value: value to be added
        """
        assert isinstance(values, list)
        self.modifications.setdefault(dn, []).append(
            dict(
                op="add",
                attr=attr,
                values=values,
            )
        )

    def remove_value(self, dn, attr, values=None):
        """
        Remove value from LDIF.
        :param dn: DN of entry
        :param attr: attribute name
        :param value: value to be removed, if value is None, attribute will
        be removed
        """
        assert values is None or isinstance(values, list)
        self.modifications.setdefault(dn, []).append(
            dict(
                op="del",
                attr=attr,
                values=values,
            )
        )

    def replace_value(self, dn, attr, values):
        """
        Replace values in LDIF with new value.
        :param dn: DN of entry
        :param attr: attribute name
        :param value: new value for atribute
        """
        assert isinstance(values, list)
        self.remove_value(dn, attr)
        self.add_value(dn, attr, values)

    def modifications_from_ldif(self, ldif_file):
        """
        Parse ldif file. Default operation is add, only changetypes "add"
        and "modify" are supported.
        :param ldif_file: an opened file for read
        :raises: ValueError
        """
        parser = ldif.LDIFRecordList(ldif_file)
        parser.parse()

        last_dn = None
        for dn, entry in parser.all_records:
            if dn is None:
                # ldif parser return None, if records belong to previous DN
                dn = last_dn
            else:
                last_dn = dn

            if "replace" in entry:
                for attr in entry["replace"]:
                    attr = attr.decode('utf-8')
                    try:
                        self.replace_value(dn, attr, entry[attr])
                    except KeyError:
                        raise ValueError("replace: {dn}, {attr}: values are "
                                         "missing".format(dn=dn, attr=attr))
            elif "delete" in entry:
                for attr in entry["delete"]:
                    attr = attr.decode('utf-8')
                    self.remove_value(dn, attr, entry.get(attr, None))
            elif "add" in entry:
                for attr in entry["add"]:
                    attr = attr.decode('utf-8')
                    try:
                        self.replace_value(dn, attr, entry[attr])
                    except KeyError:
                        raise ValueError("add: {dn}, {attr}: values are "
                                         "missing".format(dn=dn, attr=attr))
            else:
                logger.error("Ignoring entry: %s : only modifications "
                             "are allowed (missing \"changetype: "
                             "modify\")", dn)

    def handle(self, dn, entry):
        if dn in self.modifications:
            self.dn_updated.add(dn)
        for mod in self.modifications.get(dn, []):
            attr_name = mod["attr"]
            values = mod["values"]

            if mod["op"] == "del":
                # delete
                attribute = entry.setdefault(attr_name, [])
                if values is None:
                    attribute = []
                else:
                    attribute = [v for v in attribute if v not in values]
                if not attribute:  # empty
                    del entry[attr_name]
            elif mod["op"] == "add":
                # add
                attribute = entry.setdefault(attr_name, [])
                attribute.extend([v for v in values if v not in attribute])
            else:
                assert False, "Unknown operation: %r" % mod["op"]

        self.writer.unparse(dn, entry)

    def parse(self):
        ldif.LDIFParser.parse(self)

        # check if there are any remaining modifications
        remaining_changes = set(self.modifications.keys()) - self.dn_updated
        for dn in remaining_changes:
            logger.error(
                "DN: %s does not exists or haven't been updated", dn)


def remove_keytab(keytab_path):
    """
    Remove Kerberos keytab and issue a warning if the procedure fails

    :param keytab_path: path to the keytab file
    """
    try:
        logger.debug("Removing service keytab: %s", keytab_path)
        os.remove(keytab_path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logger.warning("Failed to remove Kerberos keytab '%s': %s",
                           keytab_path, e)
            logger.warning("You may have to remove it manually")


def remove_ccache(ccache_path=None, run_as=None):
    """
    remove Kerberos credential cache, essentially a wrapper around kdestroy.

    :param ccache_path: path to the ccache file
    :param run_as: run kdestroy as this user
    """
    logger.debug("Removing service credentials cache")
    kdestroy_cmd = [paths.KDESTROY]
    if ccache_path is not None:
        logger.debug("Ccache path: '%s'", ccache_path)
        kdestroy_cmd.extend(['-c', ccache_path])

    try:
        ipautil.run(kdestroy_cmd, runas=run_as, env={})
    except ipautil.CalledProcessError as e:
        logger.warning(
            "Failed to clear Kerberos credentials cache: %s", e)


def restart_dirsrv(instance_name="", capture_output=True):
    """
    Restart Directory server and perform ldap reconnect.
    """
    api.Backend.ldap2.disconnect()
    services.knownservices.dirsrv.restart(instance_name=instance_name,
                                          capture_output=capture_output,
                                          wait=True, ldapi=True)
    api.Backend.ldap2.connect()


def default_subject_base(realm_name):
    return DN(('O', realm_name))


def default_ca_subject_dn(subject_base):
    return DN(('CN', 'Certificate Authority'), subject_base)
