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

package templates.gcp.GCPGlbCertificateConstraintV1

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
	asset.asset_type == "compute.googleapis.com/targetHttpsProxy"

	ssl_certificates := asset.resource.data.sslCertificates

	#trace(sprintf("proxy certificates %v",[ssl_certificates]))

	target_certificates := params.certificates

	#trace(sprintf("allowed certificates %v",[target_certificates]))
	matches := cast_set(ssl_certificates) - cast_set(target_certificates)

	#trace(sprintf("matches %v",[matches]))
	count(matches) > 0

	message := sprintf("%v has certificates that are not whitelisted %v", [asset.name, matches])
	metadata := {
		"targetHttpsProxy": asset.name,
		"deniedCertificates": matches,
	}
}
