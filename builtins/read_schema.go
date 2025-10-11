package builtins

import (
	"errors"
	// "fmt"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	authzed "github.com/umbrellaassociates/opa-spicedb/plugins/spicedb"
)
var ReadSchemaBuiltinBuiltinDecl = &rego.Function{
	Name: "spicedb.read_schema",
	Decl: types.NewFunction(
		nil,           // no input arguments
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a string
	Nondeterministic: true,
}

func ReadSchemaBuiltinImpl(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {

	// get client
	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	// do query
	resp, err := client.ReadSchema(bctx.Context, &authzedpb.ReadSchemaRequest{})

	if err != nil {
		return nil, err
	}

	term,err := ast.InterfaceToValue(resp)
	if err != nil {
		return nil, err
	}


	return ast.NewTerm(term), nil

}
