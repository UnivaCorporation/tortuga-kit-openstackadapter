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

# == Class: rotuga_kit_openstackadapter::management
#
# Full description of class tortuga_kit_openstack here.
#
# === Parameters
#
# Document parameters here.
#
# [*sample_parameter*]
#   Explanation of what this parameter affects and what it defaults to.
#   e.g. "Specify one or more upstream ntp servers as an array."
#
# === Variables
#
# Here you should define a list of variables that this module would require.
#
# [*sample_variable*]
#   Explanation of how this variable affects the funtion of this class and if
#   it has a default. e.g. "The parameter enc_ntp_servers must be set by the
#   External Node Classifier as a comma separated list of hostnames." (Note,
#   global variables should be avoided in favor of class parameters as
#   of Puppet 2.6.)
#
# === Examples
#
#  class { tortuga_kit_openstack:
#    servers => [ 'pool.ntp.org', 'ntp.local.company.com' ],
#  }
#
# === Authors
#
# Author Name <author@domain.com>
#
# === Copyright
#
# Copyright 2013 Your name here, unless otherwise noted.
#

class rotuga_kit_openstackadapter::management::package {
  require tortuga::packages
}

class rotuga_kit_openstackadapter::management::post_install {
  require rotuga_kit_openstackadapter::management::package

  tortuga::run_post_install { "openstack_${compdescr}_post_install":
    kitdescr  => $kitdescr,
    compdescr => $compdescr,
    notify    => Class['tortuga_kit_base::installer::webservice::server'],
  }
}
class rotuga_kit_openstackadapter::management::config {
  require tortuga_kit_base::installer::apache
  require rotuga_kit_openstackadapter::management::post_install

  include tortuga::config
}

class rotuga_kit_openstackadapter::management {
  contain rotuga_kit_openstackadapter::management::package
  contain rotuga_kit_openstackadapter::management::post_install
  contain rotuga_kit_openstackadapter::management::config

  $compdescr = "management-${rotuga_kit_openstackadapter::config::major_version}"
}
