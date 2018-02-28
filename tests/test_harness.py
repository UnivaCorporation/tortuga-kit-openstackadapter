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

import sys
import pprint

from tortuga.softwareprofile import softwareProfileFactory
from tortuga.hardwareprofile import hardwareProfileFactory

import tortuga.resourceAdapter.openstack


hwProfileName = 'hpcloud'
hwProfileName = 'rackspace'

hwProfile = hardwareProfileFactory.getHardwareProfileApi().getHardwareProfile(hwProfileName)
swProfile = softwareProfileFactory.getSoftwareProfileApi().getSoftwareProfile('Compute')

openstack = tortuga.resourceAdapter.openstack.Openstack()

session = openstack._Openstack__initSession(hwProfile=hwProfile, swProfile=swProfile)

# pprint.pprint(openstack._Openstack__openstack_get_flavors(session))

# Get list of available networks

headers = {}
# import pdb; pdb.set_trace()

# networks = openstack._Openstack__openstack_compute_get_request(session, '/os-floating-ips', headers, expected_status=(200,))

# pprint.pprint(networks)

# sys.exit(0)


def __openstack_get_networks(session):
    networks = openstack._Openstack__openstack_network_get_request(session, '/v2.0/networks', headers, expected_status=(200,))

    if not 'networks' in networks:
        pprint.pprint('Error: unable to get networks [%s]' % (networks))

        sys.exit(1)

    return networks

def __openstack_get_routed_network(session, name=None):
    networks = __openstack_get_networks(session)

    for network in networks['networks']:
        if name and networks['name'] != name:
            continue

        if 'router:external' in network and network['router:external']:
            break
    else:
        print('Error: unable to find externally routed network')

        sys.exit(1)

    return network


def __openstack_allocate_floating_ip(session):
    network = __openstack_get_routed_network(session)

    print(network)

    pool = network['name']

    print(pool)

    response = openstack._Openstack__openstack_compute_post_request(session, '/os-floating-ips', headers, expected_status=(200,))

    pprint.pprint(response)

__openstack_allocate_floating_ip(session)
