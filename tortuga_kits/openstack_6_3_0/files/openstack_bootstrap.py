#!/usr/bin/env python

# Copyright 2008-2018 Univa Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import subprocess
import urllib.request, urllib.error, urllib.parse
import platform
import time
import base64
import json

### SETTINGS


def runCommand(cmd, retries=1):
    for nRetry in range(retries):
        p = subprocess.Popen(cmd, shell=True)

        retval = p.wait()
        if retval == 0:
            break

        time.sleep(5 + 2 ** (nRetry * 0.75))
    else:
        return -1

    return retval

def _installPackage(pkgList, yumopts=None, retries=10):
    cmd = 'yum'

    if yumopts:
        cmd += ' ' + yumopts

    cmd += ' -y install %s' % (pkgList)

    retval = runCommand(cmd, retries)
    if retval != 0:
        raise Exception('Error installing package [%s]' % (pkgList))

def installEPEL(vers):
    epelbaseurl = ('http://dl.fedoraproject.org/pub/epel'
                   '/epel-release-latest-%s.noarch.rpm' % (vers))

    runCommand('rpm -ivh %s' % (epelbaseurl))


def _isPackageInstalled(pkgName):
    return (runCommand('rpm -q --quiet %s' % (pkgName)) == 0)


def installPuppet(vers):
    pkgname = 'puppetlabs-release-pc1'

    url = 'http://yum.puppetlabs.com/%s-el-%s.noarch.rpm' % (pkgname, vers)

    bRepoInstalled = _isPackageInstalled(pkgname)

    if not bRepoInstalled:
        retval = runCommand('rpm -ivh %s' % (url), 5)
        if retval != 0:
            sys.stderr.write(
                'Error: unable to install package \"{0}\"\n'.format(pkgname))

            sys.exit(1)

    # Attempt to install puppet
    if not _isPackageInstalled('puppet-agent'):
        _installPackage('puppet-agent')


def setHostName():
    url = 'https://%s:%s/v1/identify-node' % (installerIpAddress, port)

    req = urllib.request.Request(url)

    req.add_header(
        'Authorization',
        'Basic ' + base64.standard_b64encode(
            '%s:%s' % (cfmUser, cfmPassword)))

    for nCount in range(5):
        try:
            response = urllib.request.urlopen(req)
            break
        except urllib.error.URLError as ex:
            pass
        except urllib.error.HTTPError as ex:
            if ex.code == 401:
                raise Exception(
                    'Invalid Tortuga webservice credentials')
            elif ex.code == 404:
                # Unrecoverable
                raise Exception(
                    'URI not found; invalid Tortuga webservice'
                    ' configuration')

            time.sleep(2 ** (nCount + 1))
    else:
        raise Exception('Unable to communicate with Tortuga webservice')

    d = json.load(response)

    if response.code != 200:
        if 'error' in d:
            errmsg = 'Tortuga webservice error: msg=[%s]' % (
                d['error']['message'])
        else:
            errmsg = 'Tortuga webservice internal error'

        raise Exception(errmsg)

    h = d['node']['name']

    runCommand('hostname %s' % (h))

    with open('/etc/sysconfig/network', 'a') as fp:
        fp.write('HOSTNAME=\"%s\"\n' % (h))

    return h


def updateResolver(domainName):
    with open('/etc/resolv.conf', 'w') as fp:
        if domainName:
            fp.write('search %s\n' % (domainName))

        fp.write('nameserver %s\n' % (installerIpAddress))


def bootstrapPuppet():
    with open('/etc/hosts', 'a+') as fp:
        fp.write('%s\t%s\n' % (installerIpAddress, installerHostName))

    cmd = ('/opt/puppetlabs/bin/puppet agent'
           ' --logdest /tmp/puppet_bootstrap.log'
           ' --no-daemonize --onetime --server %s'
           ' --waitforcert 120' % (installerHostName))

    runCommand(cmd)


def main():
    vals = platform.dist()

    vers = vals[1].split('.')[0]

    # Install EPEL repository on CentOS
    if not _isPackageInstalled('epel-release') and \
       vals[0].lower() in ['centos', 'redhat']:
        installEPEL(vers)

    h = setHostName()

    domainName = None
    if '.' in h:
        domainName = h.split('.', 1)[1]

    updateResolver(domainName)

    installPuppet(vers)

    bootstrapPuppet()


if __name__ == '__main__':
    main()
