package api

import "context"

type ObjectACL struct {
	Config       string
	Owner        Actor
	LifeID       ID
	Audience     string
	Participants []ID
	Generation   Generation
}

type ObjectMetadata struct {
	Ref               BlobRef
	ACL               ObjectACL
	Origin            string
	SourceOperationID ID
	CommittedAt       Timestamp
}

type ObjectWrite struct {
	ObjectKey ID
	Class     string
	Bytes     []byte
	SHA256    Digest
	ACL       ObjectACL
	Origin    string
	InputRefs []BlobRef
}

type UploadLease struct {
	ID            ID
	Class         string
	DeclaredBytes int64
	SHA256        Digest
	ACL           ObjectACL
	ExpiresAt     Timestamp
}

type RetainObjectRequest struct {
	Intent InternalIntent
	Object ObjectWrite
}

type ObjectStore interface {
	ObjectMetadata(context.Context, Scope, ID) (ObjectMetadata, error)
	Upload(context.Context, Scope, ID) (UploadLease, error)
	RetainObject(context.Context, Scope, RetainObjectRequest) (BlobRef, error)
}
