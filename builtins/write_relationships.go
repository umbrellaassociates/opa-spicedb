package builtins

import (
	"errors"
	"fmt"
	authzedpb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	authzed "github.com/umbrellaassociates/opa-spicedb/plugins/spicedb"
	"google.golang.org/grpc/status"
)

type writeRelationshipsResult struct {
	Token  ZedToken `json:"writtenAt"`
	Result bool     `json:"result"`
}

var WriteRelationshipsBuiltinDecl = &rego.Function{
	Name: "spicedb.write_relationships",
	Decl: types.NewFunction(
		types.Args(
			types.Named("writes",
				types.NewAny(
					types.NewArray(nil, types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
					types.NewSet(types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
				),
			),
			types.Named("updates",
				types.NewAny(
					types.NewArray(nil, types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
					types.NewSet(types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
				),
			),
			types.Named("deletes",
				types.NewAny(
					types.NewArray(nil, types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
					types.NewSet(types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))),
				),
			),
		),
		types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))), // Returns a structure
	Nondeterministic: true,
}

func convertToArray(term *ast.Term) (*ast.Array, error) {
	// Convert the Term to an Array

	collection := term.Value

	var array *ast.Array

	// Convert the input to an ast.Array if it is an ast.Set, otherwise use the array directly
	switch c := collection.(type) {
	case *ast.Array:
		array = c
	case ast.Set:
		// Convert ast.Set to ast.Array
		// todo: try to avoid extra iteration
		array = ast.NewArray()
		c.Foreach(func(elem *ast.Term) {
			array = array.Append(elem)
		})
	default:
		return nil, fmt.Errorf("expected array or set, got %v", collection)
	}

	return array, nil
}

func generateAuthzedOperationTupel(operationStr string, tupels []relationshipStruct) ([]*authzedpb.RelationshipUpdate, error) {
	var updateRelationships []*authzedpb.RelationshipUpdate
	var update_operation authzedpb.RelationshipUpdate_Operation


	switch operationStr {
	case "TOUCH":
		update_operation = authzedpb.RelationshipUpdate_OPERATION_TOUCH
	case "WRITE":
		update_operation = authzedpb.RelationshipUpdate_OPERATION_CREATE
	case "DELETE":
		update_operation = authzedpb.RelationshipUpdate_OPERATION_DELETE
	default:
		update_operation = authzedpb.RelationshipUpdate_OPERATION_UNSPECIFIED
	}

	// Iterate over input tupels
	for _, update_tupel := range tupels {

		if update_tupel.ResourceType == "" {
			return nil, fmt.Errorf("resoureType not set: '%s'", update_tupel)
		}
		if update_tupel.ResourceId == "" {
			return nil, fmt.Errorf("resoureId not set: '%s'", update_tupel)
		}
		if update_tupel.Relationship == "" {
			return nil, fmt.Errorf("relationship not set: '%s'", update_tupel)
		}
		if update_tupel.SubjectType == "" {
			return nil, fmt.Errorf("subjectType not set: '%s'", update_tupel)
		}
		if update_tupel.SubjectId == "" {
			return nil, fmt.Errorf("subjectId not set: '%s'", update_tupel)
		}

		resourceReference := &authzedpb.ObjectReference{
			ObjectType: authzed.Schemaprefix + update_tupel.ResourceType,
			ObjectId:   update_tupel.ResourceId,
		}

		relationship := update_tupel.Relationship

		subjectReference := &authzedpb.SubjectReference{Object: &authzedpb.ObjectReference{
			ObjectType: authzed.Schemaprefix + update_tupel.SubjectType,
			ObjectId:   update_tupel.SubjectId,
		}}


		relationshipStruct := &authzedpb.Relationship{
			Resource: resourceReference,
			Relation: relationship,
			Subject:  subjectReference,
		}

		updateTupel := &authzedpb.RelationshipUpdate{
			Operation:    update_operation,
			Relationship: relationshipStruct,
		}

		updateRelationships = append(updateRelationships, updateTupel)

	}

	return updateRelationships, nil
}

func renderErr(err error) *ast.Term {
	error_result := ErrorStruct{"Error", fmt.Sprintf("%s", err)}
	var error_term, _ = ast.InterfaceToValue(error_result)
	return ast.NewTerm(error_term)
}

type relationshipStruct struct {
	ResourceType string `json:"resourceType"`
	ResourceId   string `json:"resourceId"`
	Relationship string `json:"relationship"`
	SubjectType  string `json:"subjectType"`
	SubjectId    string `json:"subjectId"`
}

// WriteRelationshipsBuiltinImpl writes/updates a set of given relationships against spicedb.
func WriteRelationshipsBuiltinImpl(bctx rego.BuiltinContext, writesTerm, touchesTerm, deletesTerm *ast.Term) (*ast.Term, error) {
	var arrayTerm *ast.Array

	//
	// convert writesTerm
	// Ensure the argument is either an array or a set
	//
	if array, err := convertToArray(writesTerm); err != nil {
		return renderErr(err), nil
	} else {
		arrayTerm = array
	}

	var writesRelStr []relationshipStruct
	if err := ast.As(arrayTerm, &writesRelStr); err != nil {
		return renderErr(err), nil
	}

	fmt.Println(authzed.Schemaprefix)
	//
	// convert touchesTerm
	// Ensure the argument is either an array or a set
	//
	if array, err := convertToArray(touchesTerm); err != nil {
		return renderErr(err), nil
	} else {
		arrayTerm = array
	}

	var touchesRelStr []relationshipStruct
	if err := ast.As(arrayTerm, &touchesRelStr); err != nil {
		return renderErr(err), nil
	}
	//
	// convert deletesTerm
	// Ensure the argument is either an array or a set
	//
	if array, err := convertToArray(deletesTerm); err != nil {
		return renderErr(err), nil
	} else {
		arrayTerm = array
	}
	var deletesRelStr []relationshipStruct
	if err := ast.As(arrayTerm, &deletesRelStr); err != nil {
		return renderErr(err), nil
	}

	var error_result ErrorStruct

	var updateRelationships []*authzedpb.RelationshipUpdate
	updates, err := generateAuthzedOperationTupel("WRITE", writesRelStr)
	if err != nil {
		return renderErr(err), nil
	}
	updateRelationships = append(updateRelationships, updates...)

	updates, err = generateAuthzedOperationTupel("TOUCH", touchesRelStr)
	if err != nil {
		return renderErr(err), nil
	}
	updateRelationships = append(updateRelationships, updates...)

	updates, err = generateAuthzedOperationTupel("DELETE", deletesRelStr)
	if err != nil {
		return renderErr(err), nil

	}
	updateRelationships = append(updateRelationships, updates...)

	writeRequest := &authzedpb.WriteRelationshipsRequest{
		Updates: updateRelationships,
	}
	fmt.Println(writeRequest)

	// get client
	client := authzed.GetAuthzedClient()
	if client == nil {
		return nil, errors.New("authzed client not configured")
	}

	// do query
	response, err := client.WriteRelationships(bctx.Context, writeRequest)

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
	var token string = response.WrittenAt.Token
	zedtoken := ZedToken(token)

	// construct result structure
	result := writeRelationshipsResult{zedtoken, true}
	// Convert the result into an AST Term
	term, err := ast.InterfaceToValue(result)
	if err != nil {
		return nil, err
	}

	return ast.NewTerm(term), nil

}
