#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package templates.gcp.GCPComputeExternalIpLicenseConstraintV1

import data.validator.gcp.lib as lib

###########################
# Find Whitelist Violations
###########################
deny[{
	"msg": message,
	"details": metadata,
}] {
	constraint := input.constraint
	lib.get_constraint_params(constraint, params)
	asset := input.asset
	asset.asset_type == "compute.googleapis.com/Instance"

	# Find network access config block w/ external IP
	instance := asset.resource.data
	access_config := instance.networkInterfaces[_].accessConfigs
	count(access_config) > 0

	#instance.disk[i].boot == true
	licenses := instance.disk[_].license

	# Check if instance is in blacklist/whitelist
	#matches := cast_set(licenses) & cast_set(params.licenses)
	#count(matches) == 0

	message := sprintf("%v does not have an allowed image license. Licenses: %v ", [asset.name, licenses])
	metadata := {"licenses": licenses}
}

###########################
# Rule Utilities
###########################

# Determine the overlap between instances under test and constraint
# By default (whitelist), we violate if there isn't overlap
target_instance_match_count(mode) = 0 {
	mode != "blacklist"
}

target_instance_match_count(mode) = 1 {
	mode == "blacklist"
}
