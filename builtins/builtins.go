package builtins

import (
	"github.com/open-policy-agent/opa/rego"
)

func Register() {
	rego.RegisterBuiltinDyn(checkPermissionBuiltinDecl, checkPermissionBuiltinImpl)
	rego.RegisterBuiltinDyn(lookupResourcesBuiltinDecl, lookupResourcesBuiltinImpl)
	rego.RegisterBuiltinDyn(lookupSubjectsBuiltinDecl, lookupSubjectsBuiltinImpl)
	rego.RegisterBuiltin3(WriteRelationshipsBuiltinDecl, WriteRelationshipsBuiltinImpl)
	rego.RegisterBuiltinDyn(ReadRelationshipsBuiltinDecl, ReadRelationshipsBuiltinImpl)
	rego.RegisterBuiltinDyn(DeleteRelationshipsBuiltinDecl, DeleteRelationshipsBuiltinImpl)
}
