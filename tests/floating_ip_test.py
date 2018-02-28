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

"""Test synchronization when allocating floating ips

This test is currently destructive!!!
"""

import threading
import queue
from tortuga.db.dbManager import DbManager
from tortuga.db.softwareProfilesDbHandler import SoftwareProfilesDbHandler
from tortuga.db.hardwareProfilesDbHandler import HardwareProfilesDbHandler
import tortuga.resourceAdapter.openstack
from tortuga.resourceAdapter.openstack import Openstack


queue = queue.Queue()

dbm = DbManager()


def worker_thread(thread_id):
    print('Starting thread {}'.format(thread_id))

    db_session = dbm.openSession()

    dbSoftwareProfile = SoftwareProfilesDbHandler().getSoftwareProfile(db_session, 'execd')
    dbHardwareProfile = HardwareProfilesDbHandler().getHardwareProfile(db_session, 'openstack')

    adapter = Openstack()

    configDict = adapter.getResourceAdapterConfig('openstack')

    session = adapter._Openstack__initSession(
        configDict, swProfile=dbSoftwareProfile,
        hwProfile=dbHardwareProfile)

    print('Currently allocated floating IPs: [{0}]'.format(
        ' '.join([floating_ip['ip'] for floating_ip in adapter._get_allocated_floating_ips(session)])))

    while True:
        item = queue.get()

        try:
            print('Thread {} requesting {} floating ips'.format(
                thread_id, item))

            floating_ips = adapter._get_floating_ips(session, item)

            floating_ips = floating_ips[0] + floating_ips[1]

            print('Got: {}'.format(' '.join([floating_ip['ip'] for floating_ip in floating_ips])))
            # print 'Got: {}'.format(floating_ips)
        finally:
            queue.task_done()


for thread_id in range(2):
    thread = threading.Thread(target=worker_thread, args=(thread_id,))
    thread.daemon = True
    thread.start()

queue.put(1)
queue.put(1)
queue.put(1)
queue.put(1)
queue.put(1)

queue.join()

print('session_floating_ips:', tortuga.resourceAdapter.openstack.session_floating_ips)
