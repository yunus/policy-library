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
"""
Create a new rule with proper CRD naming. The default rule is based on vm-external-ip
"""

import shutil
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import sys
import datetime
import logging as log
log.basicConfig(level=log.INFO)


resource = sys.argv[1]
resources = resource.split("-")
feature = sys.argv[2]
features = feature.split("-")
version = sys.argv[3]
human_readable_name = sys.argv[4]

metadata_name = "gcp-{}-{}-{}".format(resource.lower(),
                                      feature.lower(), version.lower())
capital_resource = "".join(map(lambda x: x.capitalize(), resources))
capital_feature = "".join(map(lambda x: x.capitalize(), features))

crd_kind = "GCP{}{}Constraint{}".format(
    capital_resource, capital_feature, version.capitalize())
crd_plural = "gcp{}{}constraints{}".format(
    capital_resource.lower(), capital_feature.lower(), version.capitalize().lower())
year = datetime.datetime.now().strftime("%Y")

log.info("CRD KIND %s", crd_kind)
log.debug("CRD PLURAL %s", crd_plural)

root_path = os.path.dirname(__file__)


def render_and_write(template_file_name, write_path_and_filename, parameters={}):
    """
    reads the jinja template, renders it and writes to given path
    """

    env = Environment(loader=FileSystemLoader(
        os.path.join(root_path, "rule_jinja_templates")))
    template = env.get_template(template_file_name)
    log.debug('Rendering from template: %s', template.name)
    rendered_template = template.render(parameters)
    log.debug(rendered_template)

    with open(write_path_and_filename, 'wb') as out:
        out.write(rendered_template.encode('utf-8'))
    log.debug('Template %s has been converted and written into %s',
              template_file_name, write_path_and_filename)


# render REGO
rego_filename = ("gcp-{}-{}.rego".format(resource.lower(),
                                         feature.lower())).replace("-", "_")
render_and_write(
    template_file_name="validator.rego.jinja2",
    write_path_and_filename=os.path.join(
        root_path, "..", "validator", rego_filename),
    parameters={"year": year, "crd_kind": crd_kind}
)
log.info("%s has been created under the validator directory. In this file you define the rego rule.", rego_filename)

# template file
template_filename = "{}.yaml".format(metadata_name.lower().replace("-", "_"))
render_and_write(
    template_file_name="constraint_template.yaml.jinja2",
    write_path_and_filename=os.path.join(
        root_path, "..", "policies", "templates", template_filename),
    parameters={
        "year": year,
        "crd_kind": crd_kind,
        "crd_plural": crd_plural,
        "metadata_name": metadata_name,
        "validator_source_name": rego_filename
    }
)
log.info("%s has been created under the policies/templates directory. In this file you define the parameters for your rego rule.", template_filename)


# create sample file
sample_filename = ("gcp_{}_{}.yaml".format(
    resource.lower(), feature.lower())).replace("-", "_")
render_and_write(
    template_file_name="sample.yaml.jinja2",
    write_path_and_filename=os.path.join(
        root_path, "..", "samples", sample_filename),
    parameters={
        "year": year,
        "crd_kind": crd_kind,
        "human_readable_name": human_readable_name
    }
)
log.info("%s has been created under the samples directory. You should copy this file under policies/constraints and provide parameters.", sample_filename)

# create test rego
test_rego_filename = ("gcp_{}_{}_test.rego".format(resource.lower(),
                                                   feature.lower())).replace("-", "_")
test_fixture_directory_basename = ("gcp_{}_{}".format(
    resource.lower(), feature.lower())).replace("-", "_")
render_and_write(
    template_file_name="validator_test.rego.jinja2",
    write_path_and_filename=os.path.join(
        root_path, "..", "validator", test_rego_filename),
    parameters={"year": year, "crd_kind": crd_kind,
                "test_fixture_directory": test_fixture_directory_basename}
)
log.info("%s has been created under the validator directory. In this file you define the rego rule.", rego_filename)

# create fixtures
test_fixture_directory_full_path = os.path.join(
    root_path, "..", "validator", "test", "fixtures", test_fixture_directory_basename)
try:
    os.mkdir(test_fixture_directory_full_path)
    os.mkdir(os.path.join(test_fixture_directory_full_path, "assets"))
    os.mkdir(os.path.join(test_fixture_directory_full_path, "constraints"))
except(FileExistsError):
    log.warning("%s already exists", test_fixture_directory_full_path)

# create constraints
render_and_write(
    template_file_name="sample.yaml.jinja2",
    write_path_and_filename=os.path.join(
        test_fixture_directory_full_path, "constraints", "data.yaml"),
    parameters={
        "year": year,
        "crd_kind": crd_kind,
        "human_readable_name": human_readable_name
    }
)

# create example assets
shutil.copy(os.path.join(root_path, "rule_jinja_templates", "fixture_assets.json"),
            os.path.join(test_fixture_directory_full_path, "assets", "data.json"))