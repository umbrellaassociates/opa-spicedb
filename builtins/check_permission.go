package builtins

import (
	"errors"
	"fmt"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"google.golang.org/grpc/status"
	authzed "umbrella-associates/opa-spicedb/plugins/spicedb"
)

var checkPermissionBuiltinDecl = &rego.Function{
	Name: "spicedb.check_permission",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.S, types.S, types.S),           // subject, permission, resource
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a boolean
	Nondeterministic: true,
}

// Use a custom cache key type to avoid collisions with other builtins caching data!!
type checkPermissionCacheKeyType string

type checkResult struct {
	Token  ZedToken `json:"lookedUpAt"`
	Result bool     `json:"result"`
}

// checkPermissionBuiltinImpl checks the given permission requests against spicedb.
func checkPermissionBuiltinImpl(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {
	var error_result ErrorStruct

	// extract parameters
	var resourceType, resourceId, permission, subjectType, subjectId string

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

	if err := ast.As(terms[4].Value, &subjectId); err != nil {
		return nil, err
	}

	// Check if it is already cached, assume they never become invalid.
	var cacheKey = checkPermissionCacheKeyType(fmt.Sprintf("%s:%s#%s@%s:%s", resourceType, resourceId, permission, subjectType, subjectId))
	cached, ok := bctx.Cache.Get(cacheKey)
	if ok {
		return ast.NewTerm(cached.(ast.Value)), nil
	}

	subjectReference := &authzedpb.SubjectReference{Object: &authzedpb.ObjectReference{
		ObjectType: authzed.Schemaprefix + subjectType,
		ObjectId:   subjectId,
	}}

	resourceReference := &authzedpb.ObjectReference{
		ObjectType: authzed.Schemaprefix + resourceType,
		ObjectId:   resourceId,
	}

	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	resp, err := client.CheckPermission(bctx.Context, &authzedpb.CheckPermissionRequest{
		Resource:   resourceReference,
		Permission: permission,
		Subject:    subjectReference,
	})

	if err != nil { // error condition seems NOT to catch issues with the write request
		// extract if gRPC error
		if s, ok := status.FromError(err); ok {
			// Extract code & description
			error_result = ErrorStruct{s.Code().String(), s.Message()}
		} else {
			var errorstring = fmt.Sprintf("%s", err)
			error_result = ErrorStruct{"Error", errorstring}
		}

		var error_term, _ = ast.InterfaceToValue(error_result)

		return ast.NewTerm(error_term), nil
	}

	// extract ZedToken
	var token string = resp.CheckedAt.Token
	zedtoken := ZedToken(token)

	var has_permissionship bool = resp.Permissionship == authzedpb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION

	result := checkResult{zedtoken, has_permissionship}
	term, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, err
	}
	bctx.Cache.Put(cacheKey, term)

	return ast.NewTerm(term), nil
}
