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

package templates.gcp.GCPKmsGcsEnabledConstraintV1

import data.test.fixtures.gcp_kms_gcs_enabled.constraints as fixture_constraint

find_violations[violation] {
	issues := deny with input.asset as data.bucket[_]
		 with input.constraint as data.constraint

	total_issues := count(issues)

	violation := issues[_]
}

test_is_cmek_keys_enabled {
	issues := find_violations with data.bucket as data.test.fixtures.gcp_kms_gcs_enabled.assets.cmek_not_exist
		 with data.constraint as fixture_constraint

	trace(issues[_].msg)
	contains(issues[_].msg, "CMEK encryption configured")
}

test_is_label_set {
	issues := find_violations with data.bucket as data.test.fixtures.gcp_kms_gcs_enabled.assets.label_not_set
		 with data.constraint as fixture_constraint

	trace(issues[_].msg)
	contains(issues[_].msg, "does not have the required label")
}

test_hsm_does_not_exist {
	issues := find_violations with data.bucket as data.test.fixtures.gcp_kms_gcs_enabled.assets.hsm_does_not_exist
		 with data.constraint as fixture_constraint

	trace(issues[_].msg)
	contains(issues[_].msg, "does not have HSM")
}

test_location_does_not_match {
	issues := find_violations with data.bucket as data.test.fixtures.gcp_kms_gcs_enabled.assets.location_does_not_match
		 with data.constraint as fixture_constraint

	trace(issues[_].msg)
	contains(issues[_].msg, "should match key location")
}

test_name_does_not_match {
	issues := find_violations with data.bucket as data.test.fixtures.gcp_kms_gcs_enabled.assets.name_not_match
		 with data.constraint as fixture_constraint

	trace(issues[_].msg)
	contains(issues[_].msg, "is not created for this gcs bucket")
}

test_everything_is_fine {
	issues := find_violations with data.bucket as data.test.fixtures.gcp_kms_gcs_enabled.assets.everything_is_fine
		 with data.constraint as fixture_constraint

	count(issues) == 0
}
