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

package templates.gcp.GCPBackendServiceSecurityPolicyConstraintV1

import data.test.fixtures.gcp_backend_service_security_policy.assets.allowed_exception as fixture_exception
import data.test.fixtures.gcp_backend_service_security_policy.assets.violation as fixture_violation
import data.test.fixtures.gcp_backend_service_security_policy.constraints as fixture_constraints

# Find all violations on our test cases
find_violations[violation] {
	asset := data.assets[_]
	constraint := data.constraints

	issues := deny with input.asset as asset
		 with input.constraint as constraint

	total_issues := count(issues)

	violation := issues[_]
}



# Confim no violations with exception
test_backend_service_allowed_as_exception_without_armor {
	found_violations := find_violations with data.assets as fixture_exception
	  with data.constraints as fixture_constraints

	count(found_violations) = 0
}

# Confirm a violation without an exception
test_backend_service_without_cloudarmor_detected_as_violation {
	found_violations := find_violations with data.assets as fixture_violation
		 with data.constraints as fixture_constraints

	count(found_violations) = 1
}