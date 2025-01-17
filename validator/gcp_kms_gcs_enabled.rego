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
	asset.asset_type == "storage.googleapis.com/Bucket"

	bucket := asset.resource.data
	kms_key_name := default_kms_key_name(bucket)

	message := cmek_checks(asset, params, kms_key_name)

	metadata := {
		"default_kms_key_name": kms_key_name,
		"resource": asset.name,
	}
}

###########################
# Rule Utilities
###########################

default_kms_key_name(bucket) = default_kms_key_name {
	encryption := lib.get_default(bucket, "encryption", {})
	default_kms_key_name := lib.get_default(encryption, "defaultKmsKeyName", "")
}

# GCS calls EU while KMS calls EUROPE. The rest of the regions have the same naming
convert_eu_to_europe(gcs_location) = location {
	lower(gcs_location) == "eu"
	location := "europe"
}

convert_eu_to_europe(gcs_location) = location {
	lower(gcs_location) != "eu"
	location := lower(gcs_location)
}

cmek_checks(asset, params, kms_key_name) = msg {
	# is CMEK enabled?
	trace("is cmek enabled?")
	kms_key_name == ""
	msg := sprintf("%v does not have the required CMEK encryption configured.", [asset.name])
}

else = msg {
	# Check whether the label is set
	trace("is label set?")
	class_label := lib.get_default(asset.resource.data.labels, params.label_name, "")
	class_label == ""
	msg := sprintf("%v does not have the required label for %v", [asset.name, params.label_name])
}

else = msg {
	# is HSM required? if so, does the key have HSM?
	# projects/[project name]/locations/[location]/keyRings/[keyring]/cryptoKeys/[crypto key]
	trace("is hsm needed?")
	class_label := lib.get_default(asset.resource.data.labels, params.label_name, "")
	trace(sprintf("label is %v", [class_label]))
	contains(lower(class_label), lower(params.hsm_labels[_]))
	kms_key_splitted := split(kms_key_name, "/")
	key_name := kms_key_splitted[7]
	not contains(lower(key_name), "hsm")
	msg := sprintf("Kms key %v of %v does not have HSM, although the label %v=%v, requires it", [kms_key_name, asset.name, params.label_name, class_label])
}

else = msg {
	# check whether locations of the bucket and the key match
	trace("is location fine?")
	kms_key_splitted := split(kms_key_name, "/")
	key_location := kms_key_splitted[3]

	gcs_location := lib.get_default(asset.resource.data, "location", "")
	lower(key_location) != convert_eu_to_europe(gcs_location)
	msg := sprintf("GCS location %v, should match key location %v", [gcs_location, key_location])
}

else = msg {
	# check whether the bucket is using the correct key that is assigned for it
	# we check the naming of keyring, and we expect that it has "gcs" word and
	# correct project. 
	trace("does naming match gcs?")
	kms_key_splitted := split(kms_key_name, "/")
	keyring_name := kms_key_splitted[5]

	# FIXME: the keyring has project id in it, while the bucket has project number.
	# To figure out the project id, we need to make cross reference, which is not
	# possible with Config Validator as of December 2019. Google team is working on it.
	# So currently, we only check for the word "gcs" inside the name of keyring.

	#not re_match(sprintf(".*-gcs-%v.*",[asset.resource.data.projectNumber]),keyring_name)
not re_match(	".*-gcs-.*", keyring_name)

	msg := sprintf("Keyring %v is not created for this gcs bucket %v", [kms_key_name, asset.name])
}
