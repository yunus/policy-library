#
# Copyright 2018 Google LLC
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

import data.test.fixtures.iam_deny_sod.assets as fixture_assets
import data.test.fixtures.iam_deny_sod.constraints as fixture_constraints

# Find all violations on our test cases
find_violations[violation] {
	asset := data.assets[_]
	constraint := data.test_constraints
	trace(sprintf("constraints %v", [constraint]))

	issues := deny with input.asset as asset with input.constraint as constraint

	total_issues := count(issues)

	violation := issues[_]
	trace(sprintf("violatoins %v",[issues]))
	#violation := "true"
	
}

test_iam_deny_sod_violated_pairs {
	found_violations := find_violations with data.assets as fixture_assets
		 with data.test_constraints as fixture_constraints

	count(found_violations) > 0
	trace(sprintf("violations:%v", [found_violations]))
}

test_iam_deny_sod_no_violated_pairs {
	found_violations := find_violations with data.assets as fixture_assets
		 with data.test_constraints as []

	count(found_violations) == 0
	trace(sprintf("violations:%v", [found_violations]))
}

# # Test logic for allowlisting/denylisting
# test_target_instance_match_count_allowlist {
# 	target_instance_match_count("allowlist", match_count)
# 	match_count = 0
# }
# test_target_instance_match_count_denylist {
# 	target_instance_match_count("denylist", match_count)
# 	match_count = 1
# }
# Confim no violations with no assets
# test_iam_deny_sod_no_assets {
# 	found_violations := find_violations with data.assets as []
# 	count(found_violations) = 0
# }
# # Confirm no violations with no constraints
# test_iam_deny_sod_no_role_pairs {
# 	found_violations := find_violations with data.assets as fixture_assets
# 		 with data.constraints as []
# 	count(found_violations) = 0
# }
# violations_with_empty_parameters[violation] {
# 	constraints := [fixture_constraints.glb_forbid_external_ip_default]
# 	found_violations := find_violations with data.assets as fixture_assets
# 		 with data.test_constraints as constraints
# 	violation := found_violations[_]
# }
# allowlist_violations[violation] {
# 	constraints := [fixture_constraints.glb_forbid_external_ip_allowlist]
# 	found_violations := find_violations with data.assets as fixture_assets
# 		 with data.test_constraints as constraints
# 	violation := found_violations[_]
# }
# denylist_violations[violation] {
# 	constraints := [fixture_constraints.glb_forbid_external_ip_denylist]
# 	found_violations := find_violations with data.assets as fixture_assets
# 		 with data.test_constraints as constraints
# 	violation := found_violations[_]
# }
