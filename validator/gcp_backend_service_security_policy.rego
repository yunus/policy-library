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

package templates.gcp.GCPBackendServiceSecurityPolicyConstraintV1

import data.validator.gcp.lib as lib

###########################
# Find allowlist Violations
###########################
deny[{
	"msg": message,
	"details": metadata,
}] {
	constraint := input.constraint
	lib.get_constraint_params(constraint, params)
	asset := input.asset
	asset.asset_type == "compute.googleapis.com/BackendService"
	service_data := asset.resource.data

	# services that are external
	service_data.loadBalancingScheme == "EXTERNAL"

	not_have_security_policy(service_data)

	# Check if instance is in denylist/allowlist
	target_backend_services := params.backend_services

	matches := {asset.name} & cast_set(target_backend_services)

	target_instance_match_count(params.mode, desired_count)
	count(matches) == desired_count
	message := sprintf("Backend Service %v is not allowed, a cloud armor security policy has to be attached, project %v", [asset.name, asset.resource.parent])
	metadata := {"project": asset.resource.parent}
}

###########################
# Rule Utilities
###########################

# Determine the overlap between instances under test and constraint
# By default (allowlist), we violate if there isn't overlap
target_instance_match_count(mode) = 0 {
	mode != "denylist"
}

target_instance_match_count(mode) = 1 {
	mode == "denylist"
}

not_have_security_policy(service) {
	security_policy := lib.get_default(service, "securityPolicy", "nothing")
	security_policy == "nothing"
}
