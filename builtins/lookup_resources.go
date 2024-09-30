package builtins

import (
	"errors"
	"fmt"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"io"
	authzed "umbrella-associates/opa-spicedb/plugins/spicedb"
	"google.golang.org/grpc/status"
)

type ZedToken string

type lookupResult struct {
	Result             bool     `json:"result"`
	Token              ZedToken `json:"lookedUpAt"`
	ResourceObjectIds  []string `json:"resourceIds"`
	ResourceObjectType string   `json:"resourceType"`
	Permission         string   `json:"permission"`
	SubjectType        string   `json:"subjectType"`
	SubjectId          string   `json:"subjectId"`
}

type ErrorStruct struct {
	Error string `json:"error"`
	Desc  string `json:"desc"`
}

var lookupResourcesBuiltinDecl = &rego.Function{
	Name: "spicedb.lookup_resources",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.S, types.S),                    // resource, permission, subjectType
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a ObjectType
}

// Use a custom cache key type to avoid collisions with other builtins caching data!!
type lookupResourcesCacheKeyType string

// LookupResourcesBuiltinImpl checks the given permission requests against spicedb.
func lookupResourcesBuiltinImpl(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {

	// extract parameters
	var resourceType, permission, subjectType, subjectId string

	if err := ast.As(terms[0].Value, &resourceType); err != nil {
		return nil, err
	}

	if err := ast.As(terms[1].Value, &permission); err != nil {
		return nil, err
	}

	if err := ast.As(terms[2].Value, &subjectType); err != nil {
		return nil, err
	}

	if err := ast.As(terms[3].Value, &subjectId); err != nil {
		return nil, err
	}

	// Check if it is already cached, assume they never become invalid.
	var cacheKey = lookupResourcesCacheKeyType(fmt.Sprintf("%s:?#%s@%s:%s", resourceType, permission, subjectType, subjectId))
	cached, found := bctx.Cache.Get(cacheKey)
	if found {
		return ast.NewTerm(cached.(ast.Value)), nil
	}

	// construct query element: subjectReference
	subjectReference := &authzedpb.SubjectReference{Object: &authzedpb.ObjectReference{
		ObjectType: authzed.Schemaprefix + subjectType,
		ObjectId:   subjectId,
	}}

	// get client
	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	// do query
	resp, err := client.LookupResources(bctx.Context, &authzedpb.LookupResourcesRequest{
		ResourceObjectType: authzed.Schemaprefix + resourceType,
		Permission:         permission,
		Subject:            subjectReference,
	})

	if err != nil {
		return nil, err
	}

	var has_permissionship bool
	var resourceIds []string = make([]string, 0)
	var token string
	var error_result ErrorStruct

	// result is a stream, fetch elements
	for {
		result, err := resp.Recv() // fetch response element

		if err == io.EOF { // empty
			break
		}

		if err != nil { // result is an error
			// extract if gRPC error
			if s, ok := status.FromError(err); ok {
				// Extract code & description
				error_result = ErrorStruct{s.Code().String(), s.Message()}
			} else {
				var errorstring = fmt.Sprintf("%s", err)
				error_result = ErrorStruct{"Error", errorstring}
			}
			// don't continue on errors
			break
		}

		has_permissionship = result.Permissionship == authzedpb.LookupPermissionship_LOOKUP_PERMISSIONSHIP_HAS_PERMISSION
		if !has_permissionship == true { // skip if no permission
			continue
		}

		// append resourceId
		resourceIds = append(resourceIds, result.ResourceObjectId)

		if token == "" { // save token
			token = result.LookedUpAt.Token
		}
	}

	// previous for-look broke with error, return error struct
	if error_result.Error != "" {
		var error_term, _ = ast.InterfaceToValue(error_result)
		return ast.NewTerm(error_term), nil
	}

	// extract ZedToken
	zedtoken := ZedToken(token)
	// construct result structure

	result := lookupResult{true, zedtoken, resourceIds, resourceType, permission, subjectType, subjectId}
	// Convert the result into an AST Term
	term, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, err
	}
	bctx.Cache.Put(cacheKey, term)

	return ast.NewTerm(term), nil

}
