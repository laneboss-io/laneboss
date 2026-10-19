package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ReadProjectionOperationID binds a generated immutable read output to its
// exact frame and principal. It is a pin only; the store independently checks
// native/read authority, the closed component row and every retained input.
func ReadProjectionOperationID(scope Scope, object ObjectWrite) (ID, error) {
	if scope.Frame == nil {
		return "", &Error{Code: CodeUnauthenticated, Message: "read projection has no verified frame"}
	}
	frame, err := CanonicalJSON(scope.Frame.Bytes())
	if err != nil {
		return "", err
	}
	pin, err := json.Marshal(struct {
		Frame  []byte
		Object ObjectWrite
	}{frame, object})
	if err != nil {
		return "", err
	}
	principal := scope.Actor.Kind + ":" + string(scope.Actor.ID) + ":" + string(scope.Actor.LifeID)
	sum := sha256.Sum256(append([]byte(principal+":"), pin...))
	return ID(hex.EncodeToString(sum[:])), nil
}
