package builtins

import (
	"errors"
	"fmt"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	authzed "github.com/umbrellaassociates/opa-spicedb/plugins/spicedb"
)

type deleteRelationshipsResult struct {
	Result bool     `json:"result"`
	Token  ZedToken `json:"deletedAt"`
}

var DeleteRelationshipsBuiltinDecl = &rego.Function{
	Name: "spicedb.delete_relationships",
	Decl: types.NewFunction(
		types.Args(types.S, types.S, types.A, types.S, types.S),           // resourceType, resourceId, relationship, subjectType, subjectId
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a ObjectType
}

// Use a custom cache key type to avoid collisions with other builtins caching data!!
type DeleteRelationshipsCacheKeyType string

// LookupResourcesBuiltinImpl checks the given permission requests against spicedb.
func DeleteRelationshipsBuiltinImpl(bctx rego.BuiltinContext, terms []*ast.Term) (*ast.Term, error) {

	// extract parameters
	var resourceType, resourceId, relationship, subjectType, subjectId string

	if err := ast.As(terms[0].Value, &resourceType); err != nil {
		fmt.Println("error", err)
		return nil, err
	}

	if err := ast.As(terms[1].Value, &resourceId); err != nil {
		fmt.Println("error", err)
		return nil, err
	}

	if err := ast.As(terms[2].Value, &relationship); err != nil {
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
	var cacheKey = DeleteRelationshipsCacheKeyType(fmt.Sprintf("%s:#%s@%s:%s", resourceType, resourceId, relationship, subjectType, subjectId))
	cached, found := bctx.Cache.Get(cacheKey)
	if found {
		return ast.NewTerm(cached.(ast.Value)), nil
	}

	// construct query element: SubjectFilter

	var subjectFilter *authzedpb.SubjectFilter
	//  	fmt.Println ("## 1>", subjectFilter)
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

	if relationship != "" {
		relationshipFilter.OptionalRelation = relationship
	}

	// get client
	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	// do query
	resp, err := client.DeleteRelationships(bctx.Context, &authzedpb.DeleteRelationshipsRequest{
		RelationshipFilter: relationshipFilter,
	})

	if err != nil {
		var error_term, _ = ast.InterfaceToValue(err)
		return ast.NewTerm(error_term), nil

	}

	token := resp.DeletedAt.Token

	result := deleteRelationshipsResult{
		Result: true,
		Token:  ZedToken(token),
	}
	// Convert the result into an AST Term
	term, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, err
	}

	bctx.Cache.Put(cacheKey, term)
	//
	return ast.NewTerm(term), nil

}
