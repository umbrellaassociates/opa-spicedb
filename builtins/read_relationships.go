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
	"strings"
	authzed "github.com/umbrellaassociates/opa-spicedb/plugins/spicedb"
)

type Relationship struct {
	ResourceType string `json:"resourceType"`
	ResourceId   string `json:"resourceId"`
	Relationship string `json:"relationship"`
	SubjectType  string `json:"subjectType"`
	SubjectId    string `json:"subjectId"`
}

type readRelationshipsResult struct {
	Result        bool           `json:"result"`
	Token         ZedToken       `json:"lookedUpAt"`
	Relationships []Relationship `json:"relationships"`
}

var ReadRelationshipsBuiltinDecl = &rego.Function{
	Name: "spicedb.read_relationships",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.A, types.S, types.S),           // resourceType, resourceId, permission, subjectType, subjectId
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a ObjectType
}

// Use a custom cache key type to avoid collisions with other builtins caching data!!
type ReadRelationshipsCacheKeyType string

// LookupResourcesBuiltinImpl checks the given permission requests against spicedb.
func ReadRelationshipsBuiltinImpl(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {

	// extract parameters
	var resourceType, resourceId, permission, subjectType, subjectId string

	if err := ast.As(terms[0].Value, &resourceType); err != nil {
		fmt.Println("error", err)
		return nil, err
	}

	if err := ast.As(terms[1].Value, &resourceId); err != nil {
		fmt.Println("error", err)
		return nil, err
	}

	if err := ast.As(terms[2].Value, &permission); err != nil {
		fmt.Println("error", err)
		return nil, err
	}

	if err := ast.As(terms[3].Value, &subjectType); err != nil {
		fmt.Println("error", err)
		return nil, err
	}
	if err := ast.As(terms[4].Value, &subjectId); err != nil {
		fmt.Println("error", err)
		return nil, err
	}

	// Check if it is already cached, assume they never become invalid.
	var cacheKey = ReadRelationshipsCacheKeyType(fmt.Sprintf("%s:#%s@%s:%s", resourceType, resourceId, permission, subjectType, subjectId))
	cached, found := bctx.Cache.Get(cacheKey)
	if found {
		return ast.NewTerm(cached.(ast.Value)), nil
	}

	// construct query element: SubjectFilter

	var subjectFilter *authzedpb.SubjectFilter
	if subjectType != "" {
		subjectFilter = &authzedpb.SubjectFilter{
			SubjectType: authzed.Schemaprefix + subjectType,
			//OptionalSubjectId:   subjectId,
			// OptionalRelation: ...
		}
	}
	if subjectType != "" && subjectId != "" {
		subjectFilter = &authzedpb.SubjectFilter{
			SubjectType:       authzed.Schemaprefix + subjectType,
			OptionalSubjectId: subjectId,
			// OptionalRelation: ...
		}

	}

	// construct query element: RelationshipFilter

	relationshipFilter := &authzedpb.RelationshipFilter{
		ResourceType: authzed.Schemaprefix + resourceType,
	}
	if resourceId != "" {
		relationshipFilter.OptionalResourceId = resourceId
	}
	if subjectFilter != nil {
		relationshipFilter.OptionalSubjectFilter = subjectFilter
	}

	if permission != "" {
		relationshipFilter.OptionalRelation = permission
	}

	// get client
	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	// do query
	resp, err := client.ReadRelationships(bctx.Context, &authzedpb.ReadRelationshipsRequest{
		RelationshipFilter: relationshipFilter,
	})

	if err != nil {
		return nil, err
	}

	var readResult = readRelationshipsResult{
		Result: true,
	}
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

		relation := Relationship{
			ResourceType: strings.TrimPrefix(result.Relationship.Resource.ObjectType, authzed.Schemaprefix),
			ResourceId:   result.Relationship.Resource.ObjectId,
			Relationship: result.Relationship.Relation,
			SubjectType:  strings.TrimPrefix(result.Relationship.Subject.Object.ObjectType, authzed.Schemaprefix),
			SubjectId:    result.Relationship.Subject.Object.ObjectId,
		}
		// append resourceId
		readResult.Relationships = append(readResult.Relationships, relation)

		if token == "" { // save token
			token = result.ReadAt.Token
		}
	}

	// previous for-look broke with error, return error struct
	if error_result.Error != "" {
		var error_term, _ = ast.InterfaceToValue(error_result)
		return ast.NewTerm(error_term), nil
	}

	// extract ZedToken
	readResult.Token = ZedToken(token)

	// Convert the result into an AST Term
	term, err := ast.InterfaceToValue(readResult)
	if err != nil {
		return nil, err
	}

	bctx.Cache.Put(cacheKey, term)

	return ast.NewTerm(term), nil

}
