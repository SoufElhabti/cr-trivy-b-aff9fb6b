# METADATA
# title: CRB i012 repo-supplied Rego discriminator
# description: Benign authorized research marker; reports env-var NAMES only, never values.
# scope: package
# custom:
#   id: CRB-I012-aff9fb6b
#   avd_id: CRB-I012-aff9fb6b
#   provider: generic
#   service: general
#   severity: HIGH
#   short_code: crb-i012
#   recommended_action: none
#   input:
#     selector:
#       - type: dockerfile
package user.crb.i012

import rego.v1

# env-var NAMES only (keys), sorted, no values
envnames := concat(",", sort(object.keys(opa.runtime().env)))
rt_version := opa.runtime().version

deny contains res if {
  input.Stages
  res := result.new(sprintf("CRBI012-aff9fb6b-REGO-EXEC rtver=%s envnames=[%s]", [rt_version, envnames]), {})
}
