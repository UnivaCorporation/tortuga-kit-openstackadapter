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

import pprint

from tortuga.db.softwareProfileDbApi import SoftwareProfileDbApi
from tortuga.db.hardwareProfileDbApi import HardwareProfileDbApi
from tortuga.resourceAdapter.openstack import Openstack


def main():
    swProfileName = 'BasicCompute'
    hwProfileName = 'rackspace'

    hwProfile = HardwareProfileDbApi().getHardwareProfile(hwProfileName)

    swProfile = SoftwareProfileDbApi().getSoftwareProfile(swProfileName)

    osAdapter = Openstack()

    # import pdb; pdb.set_trace()

    session = osAdapter._Openstack__initSession(hwProfile=hwProfile, swProfile=swProfile)

    instance = osAdapter._Openstack__getInstance(session, '9d232b72-d50b-4018-8b76-febf503b722f')

    # pprint.pprint(instance)

    # print osAdapter._Openstack__openstack_get_public_ip(instance)


if __name__ == '__main__':
    main()
