package builtins

import (
	"errors"
	"fmt"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"google.golang.org/grpc/status"
	"io"
	authzed "umbrella-associates/opa-spicedb/plugins/spicedb"
)

type lookupSubjectsResult struct {
	Result             bool     `json:"result"`
	Token              ZedToken `json:"lookedUpAt"`
	ResourceObjectId   string   `json:"resourceId"`
	ResourceObjectType string   `json:"resourceType"`
	Permission         string   `json:"permission"`
	SubjectType        string   `json:"subjectType"`
	SubjectIds         []string `json:"subjectIds"`
}

var lookupSubjectsBuiltinDecl = &rego.Function{
	Name: "spicedb.lookup_subjects",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.S, types.S),                    // resource, permission, subjectType
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a ObjectType
}

// Use a custom cache key type to avoid collisions with other builtins caching data!!
type lookupSubjectsCacheKeyType string

// lookupSubjectsBuiltinImpl checks the given permission requests against spicedb.
func lookupSubjectsBuiltinImpl(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {

	// extract parameters
	var resourceType, resourceId, permission, subjectType string

	if err := ast.As(terms[0].Value, &resourceType); err != nil {
		return nil, err
	}

	if err := ast.As(terms[1].Value, &resourceId); err != nil {
		return nil, err
	}

	if err := ast.As(terms[2].Value, &permission); err != nil {
		return nil, err
	}

	if err := ast.As(terms[3].Value, &subjectType); err != nil {
		return nil, err
	}

	// construct query element: resourceReference
	ResourceReference := &authzedpb.ObjectReference{
		ObjectType: authzed.Schemaprefix + resourceType,
		ObjectId:   resourceId,
	}

	// Check if it is already cached, assume they never become invalid.
	var cacheKey = lookupSubjectsCacheKeyType(fmt.Sprintf("%s:%s#%s@%s:?", resourceType, resourceId, permission, subjectType))
	cached, found := bctx.Cache.Get(cacheKey)
	if found {
		return ast.NewTerm(cached.(ast.Value)), nil
	}

	// get client
	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	// do query
	resp, err := client.LookupSubjects(bctx.Context, &authzedpb.LookupSubjectsRequest{
		Resource:          ResourceReference,
		Permission:        permission,
		SubjectObjectType: authzed.Schemaprefix + subjectType,
	})

	if err != nil {
		return nil, err
	}

	var has_permissionship bool
	var subjectIds []string = make([]string, 0)
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
		subjectIds = append(subjectIds, result.SubjectObjectId)

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

	result := lookupSubjectsResult{true, zedtoken, resourceType, resourceId, permission, subjectType, subjectIds}
	// Convert the result into an AST Term
	term, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, err
	}
	bctx.Cache.Put(cacheKey, term)

	return ast.NewTerm(term), nil

}
