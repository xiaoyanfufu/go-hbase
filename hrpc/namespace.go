package hrpc

import (
	"context"

	"github.com/xiaoyanfufu/go-hbase/pb"
	"google.golang.org/protobuf/proto"
)

// ListNamespaceDescriptors models a ListNamespaceDescriptors pb call.
type ListNamespaceDescriptors struct {
	base
}

// NewListNamespaceDescriptors creates a new request that lists namespaces in HBase.
func NewListNamespaceDescriptors(ctx context.Context) *ListNamespaceDescriptors {
	return &ListNamespaceDescriptors{
		base: base{
			ctx:      ctx,
			resultch: make(chan RPCResult, 1),
		},
	}
}

// Name returns the name of this RPC call.
func (l *ListNamespaceDescriptors) Name() string {
	return "ListNamespaceDescriptors"
}

// Description returns the description of this RPC call.
func (l *ListNamespaceDescriptors) Description() string {
	return l.Name()
}

// ToProto converts the RPC into a protobuf message.
func (l *ListNamespaceDescriptors) ToProto() proto.Message {
	return &pb.ListNamespaceDescriptorsRequest{}
}

// NewResponse creates an empty protobuf message to read the response of this RPC.
func (l *ListNamespaceDescriptors) NewResponse() proto.Message {
	return &pb.ListNamespaceDescriptorsResponse{}
}