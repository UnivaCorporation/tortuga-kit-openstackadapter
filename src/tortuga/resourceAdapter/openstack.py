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

# pylint: disable=no-member

import base64
import itertools
import json
import os.path
import pprint
import re
import subprocess
import threading
import urllib.parse
import uuid

import gevent
import gevent.queue
import requests
from requests.exceptions import Timeout
from tortuga.db.models.nic import Nic
from tortuga.db.models.node import Node
from tortuga.exceptions.commandFailed import CommandFailed
from tortuga.exceptions.configurationError import ConfigurationError
from tortuga.exceptions.invalidArgument import InvalidArgument
from tortuga.exceptions.nicNotFound import NicNotFound
from tortuga.exceptions.resourceNotFound import ResourceNotFound
from tortuga.os_utility import osUtility
from tortuga.resourceAdapter.resourceAdapter import ResourceAdapter
from tortuga.resourceAdapter.utility import get_provisioning_nic
from tortuga.resourceAdapterConfiguration import settings
from tortuga.utility.cloudinit import dump_cloud_config_yaml


# Lock used to synchronize access to 'session_floating_ips'
openstack_lock = threading.RLock()

session_floating_ips = []


def get_instance_name(hostname):
    return hostname.split('.', 1)[0]


class OpenStackOperationFailed(Exception):
    def __init__(self, msg, error_detail=None):
        self.msg = msg
        self.error_detail = error_detail


class Openstack(ResourceAdapter):
    __adaptername__ = 'openstack'

    DEFAULT_INSTANCE_CACHE_CONFIG_FILE = 'openstack-instance.conf'

    DEFAULT_CREATE_TIMEOUT = 900

    DEFAULT_DELETE_TIMEOUT = 300

    DEFAULT_SLEEP_TIME = 5

    DEFAULT_NETWORK_TIMEOUT = 120

    settings = {
        'username': settings.StringSetting(
            required=True,
            description='OpenStack user name',
        ),
        'password': settings.StringSetting(
            secret=True,
            description='OpenStack password',
        ),
        'tenant_id': settings.StringSetting(
            required=True,
            description='OpenStack tenant (project) name',
        ),
        'keypair': settings.StringSetting(
            required=True,
            description='Key pair name',
        ),
        'url': settings.StringSetting(
            required=True,
            description='URL of OpenStack Keystone identity service',
        ),
        'flavor': settings.StringSetting(
            required=True,
            description='Instance flavor',
        ),
        'image_id': settings.StringSetting(
            required=True,
            description='Image id',
        ),
        'user_data_script_template': settings.FileSetting(
            description='Path to user data template script',
            mutually_exclusive=['cloud_init_script_template'],
            base_path='/opt/tortuga/config/',
            overrides=['cloud_init_script_template']
        ),
        'cloud_init_script_template': settings.FileSetting(
            description='Path to cloud init script',
            mutually_exclusive=['user_data_script_template'],
            base_path='/opt/tortuga/config/',
            overrides=['user_data_script_template']
        ),
    }

    def __init__(self, addHostSession=None):
        super(Openstack, self).__init__(addHostSession=addHostSession)

        self._cacheCfgFilePath = os.path.join(
            self._cm.getRoot(), 'var',
            Openstack.DEFAULT_INSTANCE_CACHE_CONFIG_FILE)

    def __requestErrorHandler(self, response):
        self.getLogger().debug('__requestErrorHandler()')

        if response.status_code == 401:
            # Authorization failed, renew credentials
            # auth_dict = self.__requestOpenStackAuthToken(configDict)
            #
            # session['auth'] = auth_dict
            pass
        else:
            if response.status_code == 404:
                raise OpenStackOperationFailed(
                    'Requested resource not found')

            error_data = json.loads(response.text)

            if response.status_code == 413:
                raise CommandFailed(error_data['overLimit']['message'])

            if list(error_data.keys()):
                # Attempt to parse out the error
                errorClass = list(error_data.keys())[0]

                if 'message' in error_data[errorClass]:
                    pass

                if 'code' in error_data[errorClass]:
                    pass

            self.getLogger().debug(
                '__requestErrorHandler(): response=[%s]' % (
                    response.text))

            raise OpenStackOperationFailed(
                'OpenStack operation failed.', error_detail=error_data)

        return response

    def __openstack_compute_get_request(self, session, url, headers=None,
                                        expected_status=None):
        """
        Raises:
            CommandFailed
        """

        bAuthAttempted = False

        while True:
            request_url = session['auth']['compute_url'] + url

            local_headers = {
                'X-Auth-Token': session['auth']['token_id'],
            }

            headers = headers or {}

            request_headers = dict(list(local_headers.items()) + list(headers.items()))

            try:
                response = requests.get(
                    url=request_url, headers=request_headers,
                    timeout=session['config']['networktimeout'])
            except Timeout:
                u = urllib.parse.urlparse(request_url)

                errmsg = 'Timeout attempting to connect to [%s]' % (
                    '%s://%s' % (u.scheme, u.netloc))

                self.getLogger().error(errmsg)

                raise CommandFailed(errmsg)

            if response.status_code in expected_status:
                break

            if response.status_code == 401:
                # Unauthorized

                if not bAuthAttempted:
                    # Authorization required; renew credentials.

                    self.getLogger().debug(
                        '__openstack_compute_get_request(): '
                        ' attempting to renew authentication credentials')

                    try:
                        auth_dict = self.__requestOpenStackAuthToken(
                            session['config'])

                        session['auth'] = auth_dict

                        # Reattempt the operation after renewing credentials
                        continue
                    except CommandFailed:
                        # Unable to (re)authenticate using existing
                        # credentials

                        self.getLogger().error('Unable to (re)authenticate')

                        bAuthAttempted = True
                else:
                    # Already attempted to renew the credentials and the
                    # operation still failed. Bail out...

                    self.getLogger().debug(
                        '__openstack_compute_get_request():'
                        ' HTTP status [%s], response=[%s]' % (
                            response.status_code, response.text))

                    raise CommandFailed('Operation failed')
            else:
                # Unexpected response status
                self.getLogger().error(
                    'URL [%s] request failed;'
                    ' HTTP status [%s]' % (
                        request_url, response.status_code))

                raise CommandFailed(
                    'Operation failed: unexpected response')

        return response.json()

    def __openstack_compute_put_request(self, session, url, headers=None,
                                        data=None, expected_status=None): \
            # pylint: disable=unused-argument
        """
        Raises:
            CommandFailed
        """

        headers = headers or {}

        auth_token = session['auth']['token_id']

        bAuthRenewAttempted = False

        while True:
            local_headers = {
                'X-Auth-Token': auth_token,
                'Content-Type': 'application/json',
            }

            header_items = list(headers.items()) if headers else []

            request_url = session['auth']['compute_url'] + url

            self.getLogger().debug(
                '__openstack_compute_put_request(): url=[%s]' % (url))

            try:
                response = requests.put(
                    url=request_url,
                    headers=dict(list(local_headers.items()) + header_items),
                    data=json.dumps(data or {}),
                    timeout=session['config']['networktimeout'])
            except Timeout:
                u = urllib.parse.urlparse(request_url)

                errmsg = 'Timeout attempting to connect to [%s]' % (
                    '%s://%s' % (u.scheme, u.netloc))

                self.getLogger().error(errmsg)

                raise CommandFailed(errmsg)

            if response.status_code == 401:
                if not bAuthRenewAttempted:
                    bAuthRenewAttempted = True

                    self.__renewSession(session)

                    auth_token = session['auth']['token_id']

                    continue
                else:
                    # Unable to renew authentication
                    raise CommandFailed('Unable to rewew auth token')

            break

        self.getLogger().debug(
            '__openstack_compute_put_request():'
            ' HTTP status=[%s]' % (response.status_code))

        return response.json()

    def __openstack_network_get_request(self, session, url, headers=None,
                                        expected_status=None): \
            # pylint: disable=unused-argument
        """
        Make a GET request to OpenStack network server (currently Neutron)

        Raises:
            CommandFailed
        """

        headers = headers or {}

        local_headers = {
            'X-Auth-Token': session['auth']['token_id'],
        }

        self.getLogger().debug(
            '__openstack_network_get_request(): url=[%s]' % (
                session['auth']['network_url'] + url))

        request_url = session['auth']['network_url'] + url

        header_items = list(headers.items()) if headers else []

        try:
            req = requests.get(
                url=request_url,
                headers=dict(list(local_headers.items()) + header_items),
                timeout=session['config']['networktimeout'])
        except Timeout:
            u = urllib.parse.urlparse(request_url)

            errmsg = 'Timeout attempting to connect to [%s]' % (
                '%s://%s' % (u.scheme, u.netloc))

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        self.getLogger().debug(
            '__openstack_network_get_request(): text=[%s]' % (req.text))

        return req.json()

    def __openstack_compute_post_request(self, session, url, request_data,
                                         headers=None, expected_status=None):
        """
        Make a POST request to OpenStack compute server (aka Nova)

        Raises:
            CommandFailed
            OpenStackOperationFailed
        """

        headers = headers or {}

        local_headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': session['auth']['token_id'],
        }

        header_items = list(headers.items()) if headers else []

        for _ in range(5):
            req = requests.post(
                url=session['auth']['compute_url'] + url,
                data=json.dumps(request_data),
                headers=dict(list(local_headers.items()) + header_items))

            if req.status_code == 401:
                session['auth'] = self.__requestOpenStackAuthToken(
                    session['config'])

                # Retry the operation after re-initializing the auth token
                continue

            if expected_status and req.status_code not in expected_status:
                self.__requestErrorHandler(req)

            break
        else:
            raise CommandFailed('timedout')

        if req.content == '':
            return None

        return req.json()

    def __openstack_get_flavors(self, session):
        """
        Return list of 'flavor' objects

        Raises:
            CommandFailed
        """

        self.getLogger().debug('__openstack_get_flavors()')

        get_flavors_response = self.__openstack_compute_get_request(
            session, '/flavors', expected_status=(200, 203))

        if 'flavors' not in get_flavors_response:
            self.getLogger().debug(
                'Unable to get list of flavors: [%s]' % (
                    get_flavors_response))

            raise CommandFailed(
                'Unable to get flavors: [%s]' % (get_flavors_response))

        return get_flavors_response['flavors']

    def __openstack_get_flavor(self, session, name):
        """
        Find flavor matching name in available flavors.

        Raises:
            CommandFailed
        """

        flavor_list = []

        flavor = None

        for flavor in self.__openstack_get_flavors(session):
            flavor_list.append(flavor['name'])
            if name == flavor['name']:
                return flavor

        raise CommandFailed('Unable to find flavor [%s]' % (name))

    def __openstack_get_networks(self, session):
        """
        Returns list of OpenStack network objects, as queried from OpenStack
        network server.

        Raises:
            CommandFailed
        """

        headers = {}

        networks = self.__openstack_network_get_request(
            session, '/v2.0/networks', headers, expected_status=(200,))

        if 'networks' not in networks:
            raise CommandFailed('Unable to get networks [%s]' % (networks))

        return networks

    def __openstack_get_routed_network(self, session, name=None):
        """
        Returns network matching name and/or whether it has the type
        "router:external". This may not be a proper way to determining the
        routed network. If that's the case, we will need to add a
        configuration file parameter to allow the user to specify the
        external network.

        Raises:
            CommandFailed
        """

        network = None

        networks = self.__openstack_get_networks(session)

        for network in networks['networks']:
            if name and networks['name'] != name:
                continue

            if 'router:external' in network and \
                    network['router:external']:
                return network

        raise CommandFailed('Unable to find externally routed network')

    def __openstack_allocate_floating_ip(self, session, network=None):
        """
        Allocate a floating IP (from OpenStack Compute service) on the
        specified network

        Raises:
            CommandFailed
        """

        headers = {}

        if network is None:
            network = self.__openstack_get_routed_network(session)

        request_data = {
            'pool': network['name'],
        }

        try:
            response = self.__openstack_compute_post_request(
                session, '/os-floating-ips', request_data, headers,
                expected_status=(200,))
        except OpenStackOperationFailed as ex:
            errmsg = ('Unable to allocate floating IP'
                      ' (floating IP pool depleted?)')

            self.getLogger().error(errmsg + ' (ex=[%s])' % (ex))

            raise CommandFailed(errmsg)

        self.getLogger().debug(
            '__openstack_allocate_floating_ip(): response=[%s]' % (response))

        return response['floating_ip']

    def __openstack_get_tenant_networks(self, session):
        """Returns a list of private tenant (non-external) networks

        Raises:
            CommandFailed
        """

        networks_resp = self.__openstack_get_networks(session)

        networks = [
            network for network in networks_resp['networks']
            if not network['router:external']]

        if not networks:
            errmsg = 'No tenant network(s) defined!?!?'

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        return networks

    def __launchSingleInstance(self, session, name=None, user_data=None):
        """
        Launch a single instance.

        Raises:
            CommandFailed
            OpenstackOperationFailed
        """

        self.getLogger().debug('__launchSingleInstance()')

        configDict = session['config']

        flavor = self.__openstack_get_flavor(session, configDict['flavor'])

        flavor_url = _get_flavor_link(flavor)

        networks = self.__openstack_get_tenant_networks(session)

        if len(networks) == 1:
            # If there's only one network, use it
            network_ids = [networks[0]['id']]
        else:
            # Ensure specified network matches available networks

            if 'networks' not in configDict:
                errmsg = (
                    'Multiple isolated networks present, \'networks\''
                    ' must be configured')

                self.getLogger().error(errmsg)

                raise CommandFailed(errmsg)

            network_ids = []

            # Ensure configured network(s) matches available networks.
            # First non-matching network logs an error and raises an
            # exception.
            for requested_network_id in configDict['networks']:
                for avail_network in networks:
                    if requested_network_id == avail_network['id']:
                        # Found matching network
                        network_ids.append(requested_network_id)

                        break
                else:
                    errmsg = 'Network with id [%s] not found.' % (
                        requested_network_id)

                    self.getLogger().error(
                        '%s. Unable to launch instance' % (errmsg))

                    raise CommandFailed(errmsg)

        create_server_request = {
            'server': {
                'flavorRef': flavor_url,
                'imageRef': configDict['image_id'],
                'name': name if name else str(uuid.uuid4()),
                'networks': [{
                    'uuid': network_id,
                } for network_id in network_ids],
            },
        }

        if 'security_groups' in session['config']:
            create_server_request['server']['security_groups'] = [
                dict(name=security_group)
                for security_group in session['config']['security_groups']]

        if 'availability_zone' in session['config']:
            create_server_request['server']['availability_zone'] = \
                session['config']['availability_zone']

        if session['config']['provider'] != 'rackspace':
            create_server_request['server']['key_name'] = \
                configDict['keypair']

        if user_data:
            create_server_request['server']['user_data'] = \
                base64.b64encode(user_data)
        else:
            self.getLogger().debug('No user data generated')

        self.getLogger().debug(
            '__launchSingleInstance(): Prior to creating an instance')

        response = self.__openstack_compute_post_request(
            session, '/servers', create_server_request,
            expected_status=(202,))

        if 'server' not in response:
            raise CommandFailed(
                'Error launching server instance: response=[%s]' % (
                    response))

        return response['server']

    def __launchInstances(self, session, nCount=1, nodes=None):
        """
        Launch multiple instances, returns a dict keyed on instance ID.

        Returns dict keyed on instance id

        Raises:
            OpenStackOperationFailed
        """

        self.getLogger().debug(
            '__launchInstances(): Launching %d instance(s)' % (nCount))

        instances = {}

        if nodes is not None:
            instances = dict()

            for node in nodes:
                userData = self.__getUserData(session['config'], node)
                # Use node name when launching instance
                launch_resp = self.__launchSingleInstance(
                    session, name=node.name, user_data=userData)

                self.getLogger().debug(
                    '__launchInstances(): launch_resp=[%s]' % (launch_resp))

                instances[launch_resp['id']] = dict(node=node)

            return instances

        userData = self.__getUserData(session['config'], None)

        for _ in range(nCount):
            launch_resp = self.__launchSingleInstance(
                session, user_data=userData)

            self.getLogger().debug(
                '__launchInstances(): launch_resp=[%s]' % (launch_resp))

            instances[launch_resp['id']] = {}

        return instances

    def __getInstance(self, session, instance_id):
        """
        Raises:
            CommandFailed
        """

        self.getLogger().debug(
            '__getInstance(instance_id=[%s])' % (instance_id))

        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': session['auth']['token_id'],
        }

        request_url = \
            session['auth']['compute_url'] + '/servers/%s' % (instance_id)

        u = urllib.parse.urlparse(request_url)

        try:
            req = requests.get(
                url=request_url, headers=headers,
                timeout=session['config']['networktimeout'])
        except Timeout:
            errmsg = 'Timeout attempting to connect to [%s]' % (
                '%s://%s' % (u.scheme, u.netloc))

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        # self.getLogger().debug('req.text=[%s]' % (req.text))

        inst_dict = req.json()

        return inst_dict['server']

    def __waitForInstancesToLaunch(self, session, node_instance_map):
        """
        Returns a tuple of (completed, errored, unknown)
        """

        self.getLogger().debug('__waitForInstancesToLaunch()')

        workqueue = gevent.queue.JoinableQueue()

        for _ in range(len(list(node_instance_map.keys()))):
            gevent.spawn(self.__wait_for_instance, session, workqueue)

        # Create list of launched instance requests
        for instance_id, node_instance in list(node_instance_map.items()):
            # Enqueue launched instance request
            workqueue.put((instance_id, node_instance,))

        gevent.sleep(10.0)

        workqueue.join()

        bTimedOut = False

        completed = {}
        errored = {}

        for instance_id, node_instance in list(node_instance_map.items()):
            if node_instance['status'] == 'ACTIVE':
                completed[instance_id] = \
                    node_instance['server_details']
            elif node_instance['status'] == 'ERROR':
                errored[instance_id] = \
                    node_instance['server_details']

        nodeCount = len(list(node_instance_map.keys()))

        if bTimedOut:
            self.getLogger().error(
                'Timeout starting instances (%d instance(s)'
                ' requested, %s instance(s) started successfully, %s'
                ' instance(s) errored)' % (
                    nodeCount, len(list(completed.keys())), len(list(errored.keys()))))

        # Determine instances in 'unknown' state (ie. they could've been
        # started and the request timed out on the client side)

        unknown = dict.fromkeys(
            set(node_instance_map.keys()) - set(completed.keys()) -
            set(errored.keys()))

        return (completed, errored, unknown)

    def __wait_for_instance(self, session, workqueue):
        while True:
            instance_id, instance_req = workqueue.get()

            while True:
                # Check instance status
                server_details_dict = self.__getInstance(
                    session, instance_id)

                status = server_details_dict['status']

                instance_req['status'] = status
                instance_req['server_details'] = server_details_dict

                if status == 'ACTIVE':
                    self.__post_launch_action(instance_id, instance_req)

                    break
                elif status == 'ERROR':
                    break

                gevent.sleep(3.0)

            workqueue.task_done()

    def __post_launch_action(self, instance_id, instance_req):
        node = instance_req['node']

        self.getLogger().debug(
            '__post_launch_action(): node=[{0}]'.format(node.name))

    def __openstack_update_metadata(self, session, instance_id, metadata):
        data = {
            'metadata': dict(list(metadata.items())),
        }

        self.__openstack_compute_post_request(
            session, '/servers/%s/metadata' % (instance_id), data,
            expected_status=(200,))

    def __openstack_update_instance_attr(self, session, instance_id, attrs):
        self.getLogger().debug(
            '__openstack_update_instance_attr():'
            ' instance_id=[%s], attrs=[%s]' % (instance_id, attrs))

        postdata = {
            'server': attrs,
        }

        self.__openstack_compute_put_request(
            session, '/servers/%s' % (instance_id), data=postdata,
            expected_status=(200,))

    def __precreateNodesAndLaunchInstances(self, session, dbSession,
                                           addNodesRequest,
                                           dbHardwareProfile,
                                           dbSoftwareProfile):
        """
        Raises:
            (any exception raised during this workflow)
        """

        node_instance_map = {}

        # Pre-create node database entries
        nodes = self.__createNodes(dbSession, addNodesRequest['count'],
                                   dbHardwareProfile, dbSoftwareProfile)

        dbSession.add_all(nodes)

        dbSession.commit()

        try:
            # Allocate floating IP addresses for use by nodes. Since this is
            # perhaps the first point of failure (insufficient resources),
            # perform this operation prior to actually launching an instance.

            floating_ip_responses = []

            if session['config']['provider'] != 'rackspace':
                for _ in range(addNodesRequest['count']):
                    response = self.__openstack_allocate_floating_ip(session)

                    floating_ip_responses.append(response)

            instances = []

            # OpenStack does not support bulk node creation, so iterate
            # over list of Nodes, creating an OpenStack instance for
            # each one

            for node, floating_ip in itertools.zip_longest(
                    nodes,
                    [floating_ip_response['ip']
                     for floating_ip_response in floating_ip_responses],
                    fillvalue=None):
                userData = self.__getUserData(session['config'], node)

                # Now launch OpenStack instance
                response = self.__launchSingleInstance(
                    session, name=get_instance_name(node.name),
                    user_data=userData)

                instance_id = response['id']

                instances.append(instance_id)

                # Map OpenStack instance to node object
                node_instance_map[instance_id] = {
                    'node': node,
                }

                if floating_ip:
                    node_instance_map[instance_id]['ip'] = floating_ip['ip']

                    self.getLogger().info(
                        'Associating floating IP [%s] with'
                        ' node [%s]' % (floating_ip['ip'], node.name))

            return node_instance_map
        except Exception:
            self.getLogger().exception(
                'An exception occurred while launching instance(s)')

            # Determine unmapped floating ips for removal. Second argument
            # is a list of floating ips that have been mapped to nodes.
            # These shouldn't be deallocated here because they will be
            # deallocated when the mapped node is deleted.
            unmapped_floating_ip_ids = _get_unmapped_floating_ip_ids(
                floating_ip_responses,
                [node_detail['ip']
                 for node_detail in node_instance_map.values()
                 if 'ip' in node_detail])

            for floating_ip_id in unmapped_floating_ip_ids:
                self.__openstack_release_floating_ip(
                    session, floating_ip_id)

            nodes_to_be_deleted = [
                node_detail['node']
                for node_detail in node_instance_map.values()
                if 'node' in node_detail
            ]

            self.getLogger().error(
                'Cleaning up node(s): %s' % (
                    ' '.join([node.name for node in nodes_to_be_deleted])))

            # Terminate all instances. The current semantics dictate that
            # if any one node operation fails, terminate all node(s)
            # started during this transaction.
            self.deleteNode(nodes_to_be_deleted)

            # Push the exception up the stack to reported to the caller
            raise

    def __init_new_node(self, dbHardwareProfile, dbSoftwareProfile):
        node = Node()
        node.hardwareprofile = dbHardwareProfile
        node.hardwareProfileId = dbHardwareProfile.id
        node.softwareprofile = dbSoftwareProfile
        node.softwareProfileId = dbSoftwareProfile.id
        node.state = 'Discovered'
        node.isIdle = False
        node.addHostSession = self.addHostSession

        return node

    def __addActiveNodes(self, session, dbSession, addNodesRequest,
                         dbHardwareProfile, dbSoftwareProfile): \
            # pylint: disable=unused-argument
        """
        Raises:
            OpenStackOperationFailed
        """

        self.getLogger().debug('__addActiveNodes()')

        # Allocate floating ip address(es)
        if not session['config']['hosted_on_openstack']:
            self.getLogger().debug(
                '__addActiveNodes(): allocating floating ip'
                ' address(es)')

            existing_floating_ips, allocated_floating_ips = \
                self._get_floating_ips(session, addNodesRequest['count'])
        else:
            existing_floating_ips = allocated_floating_ips = []

        floating_ips = existing_floating_ips + allocated_floating_ips

        # Allocate node records
        self.getLogger().debug(
            '__addActiveNodes(): allocating node record(s)')

        nodes = self.__createNodes(dbSession, addNodesRequest['count'],
                                   dbHardwareProfile, dbSoftwareProfile,
                                   bGenerateIp=False)

        dbSession.add_all(nodes)

        dbSession.commit()

        if not session['config']['hosted_on_openstack']:
            # Associate floating ip(s) with node(s)
            self.getLogger().debug(
                '__addActiveNodes(): associating floating ip(s)'
                ' with node(s)')

            for node_, floating_ip_ in zip(nodes, floating_ips):
                node_.nics.append(Nic(ip=floating_ip_['ip'], boot=True))

        # Launch OpenStack instances
        self.getLogger().debug(
            '__addActiveNodes(): launching OpenStack instance(s)')

        try:
            node_instance_map = self.__launchInstances(session, nodes=nodes)
        except OpenStackOperationFailed as exc:
            # Clean up any allocated floating ips

            self.getLogger().debug('error_detail: [%s]' % (exc.error_detail))

            # Clean up any previously allocated floating ips
            self._release_floating_ips(session, allocated_floating_ips)

            errmsg = ''

            for _, error_detail in exc.error_detail.items():
                errmsg = 'OpenStack reported: %s' % (
                    error_detail['message'])

            raise OpenStackOperationFailed(errmsg)

        # Wait for instances to launch
        self.getLogger().debug(
            '__addActiveNodes(): waiting for instance(s) to'
            ' reach \'running\' state')

        instances_tuple = self.__waitForInstancesToLaunch(
            session, node_instance_map)

        # If the requested number of instances does not start
        # successfully, abort the operation and clean up.
        if len(list(instances_tuple[0].keys())) != addNodesRequest['count']:
            self.getLogger().error(
                'error launching instance(s); cleaning up...')

            self.__cleanup_failed_launch(
                session, instances_tuple, allocated_floating_ips)

            raise CommandFailed('Unable to start requested instances')

        # One or more instances have reached "RUNNING" state. Iterate
        # over all completed nodes
        try:
            for instance_id in instances_tuple[0].keys():
                node_instance = node_instance_map[instance_id]

                if not session['config']['hosted_on_openstack']:
                    # associated preallocated floating ip to instance

                    ip = node_instance['node'].nics[0].ip

                    self.__openstack_add_floating_ip_to_instance(
                        session, instance_id, ip)
                else:
                    instance = self.__getInstance(session, instance_id)

                    # Extract fixed ip address from first network
                    os_network_intfcs = []

                    for os_network_intfcs in \
                            instance['addresses'].values():
                        break

                    # Iterate over interfaces connected to first network
                    for intfc in os_network_intfcs:
                        if intfc['version'] == 4 and \
                                intfc['OS-EXT-IPS:type'] == 'fixed':
                            break
                    else:
                        intfc = None

                    ip = str(intfc['addr'])

                    node_instance['node'].nics = [Nic(boot=True, ip=ip)]

                node_instance['node'].state = 'Provisioned'

                dbSession.commit()

                # Perform pre-add-host actions (create DNS record for
                # newly added node)
                self._pre_add_host(
                    node_instance['node'].name,
                    dbHardwareProfile.name,
                    dbSoftwareProfile.name,
                    ip)

                # Update the instance cache
                self.instanceCacheSet(node_instance['node'].name, {
                    'instance': instance_id,
                    'resource_adapter_configuration':
                    addNodesRequest['resource_adapter_configuration'],
                })
        except Exception:
            # If _anything_ happens during this workflow, we have
            # OpenStack instances that need to be cleaned up.
            self.getLogger().exception('Error launching instance(s)')

            for instance_id, details in node_instance_map.items():
                self.__terminateInstance(session, instance_id)

                # If the instance was successfully associated with a node
                # record, delete the mapping.
                if 'node' in details:
                    self.instanceCacheDelete(details['node'].name)

            raise

        # Return dict of successfully added nodes keyed by instance_id
        return [tmp_node['node']
                for tmp_node in node_instance_map.values()]

    def __cleanup_failed_launch(self, session, instances_tuple,
                                allocated_floating_ips):
        """'instances_tuple' is (completed, errored, unknown)"""

        completed_instances, errored_instances, unknown_instances = \
            instances_tuple

        allocated_ips = [floating_ip['ip']
                         for floating_ip in allocated_floating_ips]

        self.getLogger().error(
            'Unable to start requested number of'
            ' instances. Cleaning up...')

        # Terminate any instances that reached "ACTIVE" state
        for instance_id, node_detail in completed_instances.items():
            if 'floating_ip' in node_detail:
                # If a floating IP was previously allocated for this node,
                # release it
                if node_detail['floating_ip']['ip'] in allocated_ips:
                    self.__openstack_release_floating_ip(
                        session, node_detail['floating_ip']['id'])

            self.__terminateInstance(session, instance_id)

        # TODO: clean up instances in "ERROR" state
        if errored_instances:
            self.getLogger().info(
                'Terminating instance(s) in error'
                ' state: %s' % (' '.join(list(errored_instances.keys()))))

            # Errored instances need to be terminated as well,
            # otherwise they could against the instance quota.

            for instance_id, details in errored_instances.items():
                if 'fault' in details:
                    self.getLogger().error(
                        'Error starting instance [%s]:'
                        ' message=[%s], code=[%s]' % (
                            instance_id,
                            details['fault']['message'],
                            details['fault']['code']))

                self.__terminateInstance(session, instance_id)

        # Terminate any instances in unknown state. These instances
        # could be still pending, and even now in "ACTIVE" state.

        if unknown_instances:
            self.getLogger().info(
                'Terminating instance(s) in unknown state:'
                ' %s' % (' '.join(list(unknown_instances.keys()))))

            for instance_id in unknown_instances.keys():
                self.__terminateInstance(session, instance_id)

    def __addIdleNodes(self, session, dbSession, addNodesRequest,
                       dbHardwareProfile, dbSoftwareProfile):
        """
        Raises:
            CommandFailed
        """

        self.getLogger().debug('__addIdleNodes()')

        # TODO: validate IP only when not running on OpenStack
        # bValidateIp = True

        added_nodes = []

        nodeCount = addNodesRequest['count']

        nodeDetails = addNodesRequest['nodeDetails'] \
            if 'nodeDetails' in addNodesRequest else []

        for _, nodeDetail in itertools.zip_longest(
                list(range(nodeCount)), nodeDetails, fillvalue={}):
            addNodeRequest = {
                'addHostSession': self.addHostSession,
            }

            addNodesRequest['nics'] = []

            for dbHardwareProfileNetwork in \
                    dbHardwareProfile.hardwareprofilenetworks:
                addNodeRequest['nics'].append(
                    dict(device=dbHardwareProfileNetwork.networkdevice.name))

            if 'name' in nodeDetail:
                addNodeRequest['name'] = nodeDetail['name']

            node = self.nodeApi.createNewNode(
                dbSession, addNodeRequest, dbHardwareProfile,
                dbSoftwareProfile)

            dbSession.add(node)

            if 'resource_adapter_configuration' in addNodesRequest:
                self.instanceCacheSet(node.name, {
                    'resource_adapter_configuration':
                    addNodesRequest['resource_adapter_configuration']})

            self.getLogger().debug(
                'Created idle OpenStack node [%s]' % (node.name))

        return added_nodes

    def __createNodes(self, dbSession, count, dbHardwareProfile,
                      dbSoftwareProfile, bGenerateIp=True):
        self.getLogger().debug('__createNodes()')

        nodeList = []

        for _ in range(count):
            addNodeRequest = {
                'addHostSession': self.addHostSession,
            }

            node = self.nodeApi.createNewNode(
                dbSession, addNodeRequest, dbHardwareProfile,
                dbSoftwareProfile, bGenerateIp=bGenerateIp)

            node.state = 'Launching'

            if bGenerateIp:
                prov_nic = get_provisioning_nic(node)

                self._pre_add_host(node.name,
                                   dbHardwareProfile.name,
                                   dbSoftwareProfile.name,
                                   prov_nic.ip)

            nodeList.append(node)

        return nodeList

    def __requestOpenStackAuthToken(self, configDict):
        """
        Raises:
            CommandFailed
        """

        self.getLogger().debug('__requestOpenStackAuthToken()')

        payload = {
            'auth': {
                'passwordCredentials': {
                    'username': configDict['username'],
                    'password': configDict['password'],
                },
            }
        }

        if 'tenant_id' in configDict:
            payload['auth']['tenantId'] = configDict['tenant_id']
        elif 'tenant_name' in configDict:
            payload['auth']['tenantName'] = configDict['tenant_name']

        headers = {
            'Content-Type': 'application/json',
        }

        request_url = configDict['url'] + '/tokens'

        u = urllib.parse.urlparse(request_url)

        self.getLogger().debug(
            'Attempting to request auth token from [%s]' % (
                '%s://%s' % (u.scheme, u.netloc)))

        try:
            response = requests.post(
                url=request_url,
                data=json.dumps(payload),
                headers=headers, timeout=configDict['networktimeout'])
        except Timeout:
            errmsg = 'Timeout attempting to connect to [%s]' % (
                '%s://%s' % (u.scheme, u.netloc))

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        if response.status_code != 200:
            # Unable to authenticate

            errmsg = 'Unable to authenticate with host [%s]' % (
                configDict['url'])

            self.getLogger().error(
                errmsg + '. Response=[%s]' % (response.text))

            raise CommandFailed(errmsg)

        response_json = response.json()

        self.getLogger().debug(
            '__requestOpenStackAuthToken(response=[%s])' % (
                pprint.pformat(response_json)))

        if 'access' not in response_json:
            self.getLogger().debug(
                'Unable to authenticate: %s' % (response_json))

            raise CommandFailed(
                'Unable to authenticate: %s' % (response_json))

        access = response_json['access']

        token_id = access['token']['id']

        sc = access['serviceCatalog']

        compute_url = None
        network_url = None

        for service in sc:
            if compute_url is None and service['type'] == 'compute':
                # Iterate over compute endpoints finding one for our region
                endpoint = _find_endpoint_by_region(
                    service['endpoints'], configDict['region'])

                compute_url = endpoint['publicURL']
            elif configDict['provider'] != 'rackspace' and \
                    network_url is None and service['type'] == 'network':
                endpoint = _find_endpoint_by_region(
                    service['endpoints'], configDict['region'])

                self.getLogger().debug(
                    '__requestOpenStackAuthToken(): endpoint=[%s]' % (
                        endpoint))

                network_url = endpoint['publicURL']

                self.getLogger().debug(
                    '__requestOpenStackAuthToken(): network_url=[%s]' % (
                        network_url))

            if compute_url and network_url:
                break

        # Rackspace doesn't support Neutron
        if network_url is None and configDict['provider'] != 'rackspace':
            err = 'compute' if compute_url is None else ''
            err += ' network' if network_url is None else ''

            errmsg = 'Unable to determine service endpoint(s): %s' % (err)

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        return {
            'token_id': token_id,
            'compute_url': compute_url,
            'network_url': network_url,
        }

    def __initSession(self, configDict, swProfile=None, hwProfile=None):
        """
        Retrieve auth token

        TODO: handle errors/exceptions
        """

        self.getLogger().debug(
            '__initSession(swProfile=[%s], hwProfile=[%s])' % (
                swProfile.name if swProfile else 'None', hwProfile.name))

        configSection = hwProfile.name

        auth_dict = self.__requestOpenStackAuthToken(configDict)

        return {
            'auth': auth_dict,
            'config': configDict,
        }

    def __renewSession(self, session):
        """
        Raises:
            CommandFailed
        """

        self.getLogger().debug('__renewSession()')

        configDict = self.getResourceAdapterConfig(
            sectionName=session['config']['sectionName'])

        auth_dict = self.__requestOpenStackAuthToken(configDict)

        session['auth'] = auth_dict

        return session

    def __closeSession(self, session): \
            # pylint: disable=unused-argument
        self.getLogger().debug('__closeSession()')

        # TODO

    def getResourceAdapterConfig(self, sectionName=None):
        '''
        TODO: sectionName will eventually be a section within the
        configuration file to delineate between settings for different
        hardware and/or software profiles

        Raises:
            ConfigurationError
        '''

        self.getLogger().debug(
            'getResourceAdapterConfig(sectionName=[%s])' % (sectionName))

        configDict = super(Openstack, self).getResourceAdapterConfig(
            sectionName=sectionName)

        configDict['sectionName'] = sectionName

        # Validate configuration options. Anything that we don't handle
        # is logged, which may indicate typos or incorrect option names

        if 'vpn' in configDict:
            raise ConfigurationError('Built-in OpenVPN support is obsolete')

        if 'sleeptime' not in configDict:
            configDict['sleeptime'] = Openstack.DEFAULT_SLEEP_TIME

        if 'createtimeout' not in configDict:
            configDict['createtimeout'] = Openstack.DEFAULT_CREATE_TIMEOUT

        if 'networktimeout' not in configDict:
            configDict['networktimeout'] = Openstack.DEFAULT_NETWORK_TIMEOUT
        else:
            configDict['networktimeout'] = int(configDict['networktimeout'])

        if 'user_data_script_template' in configDict:
            if not configDict['user_data_script_template'].startswith('/'):
                # Ensure path is fully-qualified
                configDict['user_data_script_template'] = os.path.join(
                    self._cm.getKitConfigBase(),
                    configDict['user_data_script_template'])

        # If 'region' is undefined, first available region is used
        if 'region' not in configDict:
            configDict['region'] = None

        if 'provider' not in configDict:
            configDict['provider'] = 'auto'

        if 'networks' in configDict:
            # Networks can be a comma-separated list, split it into a
            # list.
            pattern = re.compile(r'\s+')

            configDict['networks'] = re.sub(
                pattern, '', configDict['networks']).split(',')

        # Because there is no way of determining if the installer is hosted
        # on RackSpace, we require the 'hosted_on_openstack' setting if
        # the 'provider' is 'rackspace'.

        if configDict['provider'] == 'rackspace':
            if 'hosted_on_openstack' not in configDict:
                errmsg = ('Configuration item \'hosted_on_openstack\''
                          ' *must* be specified when using RackSpace')

                self.getLogger().error(errmsg)

                raise ConfigurationError(errmsg)

            # Convert the string "true" or "false" into a bool in the 'dict'
            configDict['hosted_on_openstack'] = \
                configDict['hosted_on_openstack'].lower() == 'true'
        else:
            # For all other providers, depend on the auto-detection method.
            configDict['hosted_on_openstack'] = self.__isHostedOnOpenStack()

        configDict['use_instance_hostname'] = \
            configDict['use_instance_hostname'].lower() == 'true' \
            if 'use_instance_hostname' in configDict else False

        configured_values = set(configDict.keys())

        mandatory_values = set(
            ['url', 'username', 'password', 'flavor',
             'keypair'])

        optional_values = set([
            'sleeptime', 'createtimeout',
            'user_data_script_template', 'region', 'provider', 'networks',
            'hosted_on_openstack', 'use_instance_hostname',
            'availability_zone', 'image', 'image_id',
        ])

        accepted_values = mandatory_values | optional_values

        # Validate the configuration file, ensuring the mandatory
        # configuration items are defined.
        if not mandatory_values <= configured_values:
            errmsg = ('The following mandatory configuration options'
                      ' are undefined: %s' % (' '.join(
                          mandatory_values - configured_values -
                          optional_values)))

            self.getLogger().error(errmsg)

            raise ConfigurationError(errmsg)

        # Postprocess specific config items for consistency
        if configDict['url'].endswith('/'):
            configDict['url'] = configDict['url'].rstrip('/')

        # Validate configuration options. Anything that we don't handle
        # is logged, which may indicate typos or incorrect option names
        if accepted_values - set(configDict.keys()):
            self.getLogger().info(
                'The following configuration items are'
                ' invalid: [%s]' % (' '.join(list(
                    accepted_values - set(configDict.keys())))))

        # tenant_name/tenant_id/project_name/project_id
        if 'tenant_id' in configDict and 'tenant_name' in configDict:
            raise ConfigurationError(
                'tenant_id/tenant_name settings are mutually exclusive')
        elif 'project_id' in configDict and 'project_name' in configDict:
            raise ConfigurationError(
                'project_id/project_name settings are mutually exclusive')
        elif 'project_id' in configDict and 'tenant_id' in configDict:
            raise ConfigurationError(
                'project_id/tenant_id settings are mutually exclusive')
        elif 'project_name' in configDict and 'project_id' in configDict:
            raise ConfigurationError(
                'project_name/tenant_name settings are mutually exclusive')

        # Ensure tenant_id/tenant_name/project_id/project_name are specified
        if ('tenant_id' not in configDict and
            'tenant_name' not in configDict) \
                and ('project_name' not in configDict and
                     'project_id' not in configDict):
            raise ConfigurationError(
                'project_name/tenant_name or project_id/tenant_id must'
                ' be specified')

        if 'project_name' in configDict:
            configDict['tenant_name'] = configDict['project_name']
            del configDict['project_name']
        elif 'project_id' in configDict:
            configDict['tenant_id'] = configDict['project_id']
            del configDict['project_id']

        if 'security_groups' in configDict:
            configDict['security_groups'] = \
                configDict['security_groups'].split(' ')

        # Look up 'image_id' if 'image' provided
        if 'image_id' not in configDict:
            if 'image' not in configDict:
                raise ConfigurationError(
                    'image or image_id must be specified')

        self.getLogger().debug(
            'getResourceAdapterConfig(): configDict=[%s]' % (configDict))

        return configDict

    def __getUserData(self, configDict, node):
        self.getLogger().debug('__getUserData()')

        if 'user_data_script_template' not in configDict:
            self.getLogger().warn(
                'User data script template does not exist.'
                ' Instances will be started without user data')

            if node:
                bhm = osUtility.getOsObjectFactory().getOsBootHostManager()

                user_data = bhm.get_cloud_config(node)

                if not user_data:
                    return None

                user_data_yaml = dump_cloud_config_yaml(user_data)

                self.__write_user_data(node, user_data_yaml)

                return user_data_yaml

            return None

        if 'user_data_script_template' in configDict and \
                not os.path.exists(configDict['user_data_script_template']):
            self.getLogger().warn(
                'User data script template [%s] does not'
                ' exist. Instances will be started without user data' % (
                    configDict['user_data_script_template']))

            return None

        templateFileName = configDict['user_data_script_template'] \
            if 'user_data_script_template' in configDict else None

        installerIp = self.installer_public_ipaddress

        config = {
            'installerHostName': self.installer_public_hostname,
            'installerIp': installerIp,
            'adminport': str(self._cm.getAdminPort()),
            'scheme': self._cm.getAdminScheme(),
            'cfmuser': self._cm.getCfmUser(),
            'cfmpassword': self._cm.getCfmPassword(),
        }

        with open(templateFileName) as fp:
            result = ''

            for inp in fp.readlines():
                if inp.startswith('### SETTINGS'):
                    result += '''\
installerHostName = '%(installerHostName)s'
installerIpAddress = '%(installerIp)s'
port = %(adminport)s
cfmUser = '%(cfmuser)s'
cfmPassword = '%(cfmpassword)s'
''' % (config)
                else:
                    result += inp

        return result

    def start(self, addNodesRequest, dbSession, dbHardwareProfile,
              dbSoftwareProfile=None):
        self.getLogger().debug(
            'start(addNodeRequest=[%s], dbSession=[%s],'
            ' dbHardwareProfile=[%s], dbSoftwareProfile=[%s])' % (
                addNodesRequest, dbSession, dbHardwareProfile,
                dbSoftwareProfile))

        # Must specify number of nodes for OpenStack
        if 'count' not in addNodesRequest or addNodesRequest['count'] < 1:
            raise InvalidArgument('Invalid node count')

        cfgname = addNodesRequest['resource_adapter_configuration'] \
            if 'resource_adapter_configuration' in addNodesRequest else \
            None

        configDict = self.getResourceAdapterConfig(cfgname)

        session = self.__initSession(
            configDict, swProfile=dbSoftwareProfile,
            hwProfile=dbHardwareProfile)

        if 'image' in configDict:
            configDict['image_id'] = self.__get_image_id(
                session, configDict['image'])

        try:
            if dbSoftwareProfile is None or dbSoftwareProfile.isIdle:
                return self.__addIdleNodes(
                    session, dbSession, addNodesRequest, dbHardwareProfile,
                    dbSoftwareProfile)

            nodes = self.__addActiveNodes(
                session, dbSession, addNodesRequest, dbHardwareProfile,
                dbSoftwareProfile)

            # Remove all ips from 'session_floating_ips'
            with openstack_lock:
                for node in nodes:
                    prov_nic = get_provisioning_nic(node)

                    if prov_nic.ip in session_floating_ips:
                        session_floating_ips.remove(prov_nic.ip)

            return nodes
        finally:
            self.__closeSession(session)

    def activateIdleNode(self, node, softwareProfileName,
                         softwareProfileChanged):
        """
        Raises:
            NodeNotFound
        """

        self.getLogger().debug(
            'activateIdleNode(node=[%s],'
            ' softwareProfileName=[%s], softwareProfileChanged=[%s])' % (
                node.name, softwareProfileName, softwareProfileChanged))

        configDict = self.getResourceAdapterConfig(
            self.getResourceAdapterConfigProfileByNodeName(node.name))

        session = self.__initSession(
            configDict,
            hwProfile=node.hardwareprofile,
            swProfile=node.softwareprofile)

        public_ip_address = None

        try:
            userData = self.__getUserData(session['config'], node)

            # Launch an instance
            response = self.__launchSingleInstance(
                session, name=get_instance_name(node.name),
                user_data=userData)

            instance_id = response['id']

            # Update instance cache to reflect instance just launched
            self.instanceCacheSet(node.name, {
                'instance': instance_id,
            })

            # Wait for something to happen...
            completed, errored, orphaned = self.__waitForInstancesToLaunch(
                session, [dict(node=node, instance_id=instance_id)])

            if errored:
                raise CommandFailed(
                    'Unable to activate node [%s]' % (node.name))

            if orphaned:
                raise CommandFailed('We have an orphaned instance')

            if completed:
                # This action occurs on only one node at a time, so the
                # 'completed' dict only contains a single item.
                instance_id, server_details_dict = list(completed.items())[0]

                ip = _get_fixed_ip_address(server_details_dict)

                # Set IP into Node record
                if node.nics:
                    node.nics[0].ip = ip
                else:
                    node.nics.append(Nic(ip=ip))

            node.state = 'Provisioned'
        except Exception as ex:
            excmsg = ('An exception occurred attempting to activate node'
                      ' [%s]' % (node.name))

            self.getLogger().error(excmsg)

            self.getLogger().exception(ex)

            self.getLogger().info(
                'Terminating instance [%s] associated with'
                ' node [%s]' % (instance_id, node.name))

            self.__terminateInstance(session, instance_id)

            raise CommandFailed(excmsg)
        finally:
            self.__closeSession(session)

    def transferNode(self, nodeIdSoftwareProfileTuples,
                     newSoftwareProfileName):
        '''Transfer the given idle node'''

        for node, oldSoftwareProfileName in nodeIdSoftwareProfileTuples:
            self.getLogger().debug('transferNode (node=[%s])' % (node.name))

            # simply idle and activate
            self.idleActiveNode([node])

            self.activateIdleNode(
                node,
                newSoftwareProfileName,
                (newSoftwareProfileName != oldSoftwareProfileName))

    def __openstack_compute_delete_request(self, session, url, headers=None,
                                           expected_status=None):
        """
        Raises:
            CommandFailed
        """

        headers = headers or {}

        local_headers = {
            'X-Auth-Token': session['auth']['token_id'],
        }

        request_url = session['auth']['compute_url'] + url

        header_items = list(headers.items()) if headers else []

        for _ in range(5):
            try:
                response = requests.delete(
                    url=request_url,
                    headers=dict(list(local_headers.items()) + header_items),
                    timeout=session['config']['networktimeout'])
            except Timeout:
                u = urllib.parse.urlparse(request_url)

                errmsg = 'Timeout attempting to connect to [%s]' % (
                    '%s://%s' % (u.scheme, u.netloc))

                self.getLogger().error(errmsg)

                raise CommandFailed(errmsg)

            if response.status_code == 401:
                session['auth'] = self.__requestOpenStackAuthToken(
                    session['config'])

                # Retry the operation after re-initializing the auth token
                continue

            if expected_status and \
                    response.status_code not in expected_status:
                if response.status_code != 404:
                    self.__requestErrorHandler(response)

            break
        else:
            errmsg = 'Delete instance request retry limit exceeded'

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        return response

    def __terminateInstance(self, session, instance_id):
        self.getLogger().debug(
            '__terminateInstance(instance_id=[%s])' % (instance_id))

        response = self.__openstack_compute_delete_request(
            session, '/servers/%s' % (instance_id), expected_status=(204,))

        if response.status_code == 404:
            errmsg = 'Instance [%s] not found' % (instance_id)

            self.getLogger().warn(errmsg)

    def __openstack_remove_floating_ip(self, session, instance_id,
                                       floating_ip):
        """
        'floating_ip' is an IP address (string) and *NOT* a floating_ip
        dict. Blame OpenStack, not me for the inconsistency.
        """

        self.getLogger().debug(
            '__openstack_remove_floating_ip():'
            ' instance_id=[%s], floating_ip=[%s]' % (
                instance_id, floating_ip))

        request_data = {
            'removeFloatingIp': {
                'address': floating_ip,
            }
        }

        self.__openstack_compute_post_request(
            session, '/servers/%s/action' % (instance_id), request_data,
            expected_status=(202,))

    def __openstack_release_floating_ip(self, session, floating_ip_id):
        """
        TODO: add error checking here
        """

        self.getLogger().debug(
            '__openstack_release_floating_ip():'
            ' floating_ip_id=[%s]' % (floating_ip_id))

        response = self.__openstack_compute_delete_request(
            session, '/os-floating-ips/%s' % (floating_ip_id),
            expected_status=(202,))

        if response.status_code == 404:
            self.getLogger().info(
                'Unable to deallocate floating IP [%s];'
                ' not found' % (floating_ip_id))

    def __openstack_release_floating_ip_by_ip(self, session, ip):
        self.getLogger().debug(
            '__openstack_release_floating_ip_by_ip():'
            ' ip=[%s]' % (ip))

        # Get list of all floating IPs
        floating_ips = self.__openstack_get_floating_ip_list(session)

        floating_ip = None

        for floating_ip in floating_ips:
            if floating_ip['ip'] == ip:
                break
        else:
            self.getLogger().info(
                'Floating IP [%s] has been previously deallocated' % (ip))

            return

        self.__openstack_release_floating_ip(session, floating_ip['id'])

        with openstack_lock:
            session_floating_ips.remove(floating_ip['ip]'])

    def __openstack_get_floating_ip_list(self, session):
        """
        Get list of all floating IP addresses
        """

        self.getLogger().debug('__openstack_get_floating_ip_list()')

        response = self.__openstack_compute_get_request(
            session, '/os-floating-ips', expected_status=(200,))

        if 'floating_ips' not in response:
            self.getLogger().debug(
                '__openstack_get_floating_ip_list(): response=[%s]' % (
                    response))

            raise CommandFailed('Unable to get list of floating IPs')

        return response['floating_ips']

    def __openstack_get_floating_ip_for_instance(self, session, instance_id):
        """
        Returns floating_ip object
        """

        self.getLogger().debug(
            '__openstack_get_floating_ip_for_instance():'
            ' instance_id=[%s]' % (instance_id))

        floating_ips = self.__openstack_get_floating_ip_list(session)

        floating_ip = None

        for floating_ip in floating_ips:
            if floating_ip['instance_id'] == instance_id:
                return floating_ip

        return None

    def deleteNode(self, dbNodes):
        for node in dbNodes:
            self.getLogger().debug('deleteNode(): node=[%s]' % (node.name))

            try:
                configDict = self.getResourceAdapterConfig(
                    self.getResourceAdapterConfigProfileByNodeName(node.name))

                session = self.__initSession(
                    configDict,
                    hwProfile=node.hardwareprofile,
                    swProfile=node.softwareprofile)

                if node.isIdle:
                    self.__terminateIdle(session, node)
                else:
                    self.__terminateActive(session, node)
            except (ConfigurationError, ResourceNotFound):
                self.getLogger().debug(
                    'Configuration for specified node does'
                    ' not exist; node may still be running in OpenStack')

    def __terminateIdle(self, session, node):
        self.getLogger().debug('__terminateIdle(node=[%s])' % (node.name))

    def __terminateActive(self, session, node):
        """
        Raises:
            TBD
        """

        self.getLogger().debug('__terminateActive(): node=[%s]' % (node.name))

        # Get instance id from instance cache
        node_instance = self.instanceCacheGet(node.name)

        if 'instance' not in node_instance or \
                node_instance['instance'] is None:
            self.getLogger().warn(
                'Node [%s] does not have an associated instance' % (node.name))

            return

        instance_id = node_instance['instance']

        self.__terminateInstance(session, instance_id)

        # Update the instance cache
        self.instanceCacheDelete(node.name)

        bhm = osUtility.getOsObjectFactory().getOsBootHostManager()
        bhm.deleteNodeCleanup(node)

    def __openstack_add_floating_ip_to_instance(self, session, instance_id,
                                                ip):
        url = '/servers/%s/action' % (instance_id)

        payload = {
            'addFloatingIp': {
                'address': ip,
            }
        }

        self.getLogger().debug(
            '__openstack_add_floating_ip_to_instance():'
            ' instance_id=[%s], ip=[%s]' % (instance_id, ip))

        # TODO: this should raise an exception if it failed
        response = self.__openstack_compute_post_request(
            session, url, payload, expected_status=(202,))

        self.getLogger().debug(
            '__openstack_add_floating_ip_to_instance():'
            ' response=[%s]' % (response))

    def _get_allocated_floating_ips(self, session):
        response = self.__openstack_compute_get_request(
            session, '/os-floating-ips', expected_status=(200,))

        for floating_ip in response['floating_ips']:
            if floating_ip['instance_id']:
                continue

            yield floating_ip

    def _get_floating_ips(self, session, count):
        """This is an aggregate method to use allocated
        floating ips as well as allocate addtional as necessary.

        Raises:
            CommandFailed
        """

        avail_floating_ips = []
        allocated_floating_ips = []

        try:
            existing_floating_ips = \
                [floating_ip for floating_ip in
                 self._get_allocated_floating_ips(session)]

            with openstack_lock:
                for existing_floating_ip in existing_floating_ips:
                    if existing_floating_ip['ip'] not in session_floating_ips:
                        avail_floating_ips.append(existing_floating_ip)
                        session_floating_ips.append(existing_floating_ip['ip'])

                        if len(avail_floating_ips) == count:
                            break

                if len(avail_floating_ips) < count:
                    # Allocate remainer of requested number of floating ips
                    allocated_floating_ips.extend(
                        self._allocate_floating_ips(
                            session, count - len(avail_floating_ips)))

                    session_floating_ips.extend(
                        [allocated_floating_ip['ip']
                         for allocated_floating_ip in
                         allocated_floating_ips])
        except CommandFailed:
            # Unable to allocate requested number of floating IPs

            self.getLogger().info('Deallocating unused floating IPs')

            # Clean up allocated floating ips
            self._release_floating_ips(session, allocated_floating_ips)

            raise

        return avail_floating_ips, allocated_floating_ips

    def _allocate_floating_ips(self, session, count):
        result = []

        with openstack_lock:
            while len(result) < count:
                # Attempt to allocate floating ip
                floating_ip = \
                    self.__openstack_allocate_floating_ip(session)

                if floating_ip not in session_floating_ips:
                    result.append(floating_ip)

        return result

    def _release_floating_ips(self, session, floating_ips):
        self.getLogger().info(
            'Releasing floating IPs: [{0}]'.format(
                [floating_ip['ip'] for floating_ip in floating_ips]))

        # Lock 'session_floating_ips' list prior to removing all floating
        # ips.
        with openstack_lock:
            for floating_ip in floating_ips:
                self.__openstack_release_floating_ip(
                    session, floating_ip['id'])

                if floating_ip['ip'] in session_floating_ips:
                    session_floating_ips.remove(floating_ip['ip'])

    def startupNode(self, nodeIds, remainingNodeList=None,
                    tmpBootMethod='n'):
        pass

    def getOptions(self, dbSoftwareProfile, dbHardwareProfile): \
            # pylint: disable=unused-argument
        """
        Get settings for specified hardware profile
        """
        return {}

    def idleActiveNode(self, dbNodes):
        """
        Nodes can only be idled if the Tortuga installer is not cloud-based

        Raises:
            CommandFailed
        """

        for node in dbNodes:
            self.getLogger().debug('idleActiveNode(): node=[%s]' % (node.name))

            configDict = self.getResourceAdapterConfig(
                self.getResourceAdapterConfigProfileByNodeName(node.name))

            session = self.__initSession(
                configDict,
                hwProfile=node.hardwareprofile,
                swProfile=node.softwareprofile)

            # if session['config']['hosted_on_openstack']:
            #     raise CommandFailed(
            #         'Idling nodes not supported when Tortuga installer'
            #         ' hosted on OpenStack')

            # provnic = _getProvisioningNic(node)
            #
            # deviceName = provnic.networkdevice.name

            if node.state != 'Discovered':
                # Terminate the node instance
                self.__terminateActive(session, node)

            # Remove the associated nic
            node.nics[0].ip = None

            # Remove Puppet certificate for idled node
            bhm = osUtility.getOsObjectFactory().getOsBootHostManager()
            bhm.deletePuppetNodeCert(node.name)

        return 'Discovered'

    def __isHostedOnOpenStack(self):
        """
        Returns True, if Tortuga installer detected to be running on
        OpenStack.

        NOTE: this check to determine if the installer is hosted on
        OpenStack does not work with Rackspace. Configuration loader will
        warn of this. Do not use this check on RackSpace

        Raises:
            CommandFailed
        """

        # Perform operation only once
        cmd = '/opt/puppetlabs/bin/facter --json dmi.product.name'

        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, bufsize=1)

        try:
            val = json.load(p.stdout)
        except ValueError:
            errmsg = 'Unable to determine if hosted on OpenStack.'

            self.getLogger().error(
                errmsg + ': JSON parse error on facter output')

            raise CommandFailed(
                errmsg +
                '. Use \'hosted_on_openstack\' configuration option')

        retval = p.wait()

        if retval != 0:
            self.getLogger().error(
                '\'facter\' failed; unable to determine'
                ' if hosted on OpenStack.')

            raise CommandFailed(
                'Unable to determine if hosted on OpenStack')

        if val['dmi.product.name'] is None:
            errmsg = ('Unable to determine if hosted on OpenStack.'
                      ' Use \'hosted_on_openstack\' configuration option')

            self.getLogger().error(errmsg)

            raise CommandFailed(errmsg)

        return val['dmi.product.name'] is not None and \
            'OpenStack' in val['dmi.product.name']

    def __get_image_id(self, session, name):
        """Retrieve image by name

        Raises:
            ResourceNotFound
        """
        response = self.__openstack_compute_get_request(
            session, '/images', expected_status=(200,))

        for image in response['images']:
            if image['name'].lower() == name.lower():
                return image['id']

        raise ResourceNotFound('Image [{0}] not found'.format(name))


def _getProvisioningNic(node):
    """
    Raises:
        NicNotFound
    """

    # Iterate over all nics associated with node, return first nic
    # marked as a provisioning nic or first nic without an assigned
    # ip address.
    for dbNic in node.nics:
        if dbNic.ip is None or \
                (dbNic.network and dbNic.network.type == 'provision'):
            return dbNic

    raise NicNotFound(
        'Node [%s] does not have a provisioning NIC' % (node.name))


def _get_flavor_link(flavor):
    """
    Returns URL for specified flavor

    Raises:
        CommandFailed
    """

    link = None

    for link in flavor['links']:
        if link['rel'] == 'self':
            break
    else:
        raise CommandFailed(
            'Error finding link for flavor [%s]' % (flavor['name']))

    return link['href']


def _get_fixed_ip_address(server_details_dict):
    """
    Extract fixed ip address from addresses associated instance

    Raises:
        InvalidArgument
    """

    if 'addresses' not in server_details_dict:
        raise InvalidArgument('server details dict is malformed/invalid')

    address = None

    for _, addresses in server_details_dict['addresses'].items():
        # Find the first fixed IPv4 address
        for address in addresses:
            if address['OS-EXT-IPS:type'] == 'fixed':
                break
        else:
            continue

        break
    else:
        raise CommandFailed('Unable to find fixed address')

    return address['addr']


def _get_unmapped_floating_ip_ids(floating_ip_responses,
                                  mapped_floating_ips):
    """
    Parse floating ip responses comparing the mapped floating ips with
    those unmapped, return a list of floating ip ids
    """

    ids = []

    for floating_ip_response in floating_ip_responses:
        if floating_ip_response['ip'] in mapped_floating_ips:
            continue

        ids.append(floating_ip_response['id'])

    return ids


def _find_endpoint_by_region(endpoints, region):
    """
    Raises:
        CommandFailed
    """

    for endpoint in endpoints:
        if region and endpoint['region'] != region:
            continue

        return endpoint

    raise CommandFailed('Unable to find endpoint')
