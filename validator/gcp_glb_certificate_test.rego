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

import data.test.fixtures.gcp_glb_certificate.assets as fixture_proxies
import data.test.fixtures.gcp_glb_certificate.constraints as fixture_constraints

# Find all violations on our test cases
find_violations[violation] {
	proxy := data.proxies[_]
	constraint := data.test_constraints

	issues := deny with input.asset as proxy
		 with input.constraint as constraint

	total_issues := count(issues)

	violation := issues[_]
}

# Confim no violations with no instances
test_no_proxies {
	found_violations := find_violations with data.proxies as []

	count(found_violations) == 0
}

test_notwhitelisted_certificates {
	trace(sprintf("fixture contraint %v", [fixture_constraints]))
	found_violations := find_violations with data.proxies as fixture_proxies with data.test_constraints as fixture_constraints

	count(found_violations) == 1
}
