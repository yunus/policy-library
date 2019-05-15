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
package templates.gcp.GCPCMEKRotationConstraintV1

import data.validator.gcp.lib as lib

deny[{
	"msg": message,
	"details": metadata,
}] {
	constraint := input.constraint
	lib.get_constraint_params(constraint, params)
	asset := input.asset
	asset.asset_type == "cloudkms.googleapis.com/CryptoKey"

	rotation_period_string := lib.get_default(asset.resource.data, "rotationPeriod", "99999999s")
	rotation_period := time.parse_duration_ns(rotation_period_string)

	period_string := lib.get_default(params, "period", "31536000s")
	period_to_test := time.parse_duration_ns(period_string)

	rotation_period > period_to_test
	message := sprintf("%v: CMEK Rotation Period must be or less.", [asset.name])
	metadata := {"resource": asset.name}
}
