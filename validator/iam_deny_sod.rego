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

package templates.gcp.GCPIAMDenySodConstraintV1

import data.validator.gcp.lib as lib

deny[{
	"msg": message,
	"details": metadata,
}] {
	asset_types := {
		"cloudresourcemanager.googleapis.com/Organization",
		"cloudresourcemanager.googleapis.com/Folder",
		"cloudresourcemanager.googleapis.com/Project",
	}

	input.asset.asset_type == asset_types[_]

	constraint := input.constraint
	params := lib.get_constraint_params(constraint)

	#trace(sprintf("parameters: %v",[params]))
	role_pairs := params.sod_roles
	asset := input.asset

	# asset := input
	# role_pairs := ["roles/iam.serviceAccountUse,roles/iam.securityAdmin"] #params.sod_roles

	asset.asset_type == asset_types[_]

	#trace(sprintf("assets :%v",[asset]))

	bindings := asset.iam_policy.bindings

	# violations := {role_pair: sod_members |
	# 	some i
	# 	role_pair := role_pairs[i]
	# 	sod_members := get_sod_members(role_pair, bindings)
	# }
	# the below function does the same as the above comprehension.
	violations := get_violations(role_pairs, bindings)

	# make sure that we have violations to return
	count(violations) > 0

	message := sprintf("IAM policy violations for %v due to segregation of duty roles %v", [asset.name, violations])

	metadata := {
		"resource": asset.name,
		"violations": violations,
	}
}

###########################
# Rule Utilities
###########################

get_violations(role_pairs, bindings) = [{role_pair: sod_members}] {
	role_pair := role_pairs[_]
	sod_members := get_sod_members(role_pair, bindings)
}

get_sod_members(role_pair, bindings) = sod_members {
	role_set := split(role_pair, ",")
	some i, j
	bindings[i].role == role_set[0]
	bindings[j].role == role_set[1]
	sod_members := cast_set(bindings[i].members) & cast_set(bindings[j].members)
	count(sod_members) > 0
}
