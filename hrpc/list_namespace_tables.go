package hrpc

import (
	"context"

	"github.com/xiaoyanfufu/go-hbase/pb"
	"google.golang.org/protobuf/proto"
)

// ListTableNamesByNamespace models a ListTableNamesByNamespace pb call.
type ListTableNamesByNamespace struct {
	base
	namespace string
}

// NewListTableNamesByNamespace creates a new request that lists tables in a namespace.
func NewListTableNamesByNamespace(ctx context.Context, namespace string) *ListTableNamesByNamespace {
	return &ListTableNamesByNamespace{
		base: base{
			ctx:      ctx,
			resultch: make(chan RPCResult, 1),
		},
		namespace: namespace,
	}
}

// Name returns the name of this RPC call.
func (l *ListTableNamesByNamespace) Name() string {
	return "ListTableNamesByNamespace"
}

// Description returns the description of this RPC call.
func (l *ListTableNamesByNamespace) Description() string {
	return l.Name()
}

// ToProto converts the RPC into a protobuf message.
func (l *ListTableNamesByNamespace) ToProto() proto.Message {
	return &pb.ListTableNamesByNamespaceRequest{
		NamespaceName: proto.String(l.namespace),
	}
}

// NewResponse creates an empty protobuf message to read the response of this RPC.
func (l *ListTableNamesByNamespace) NewResponse() proto.Message {
	return &pb.ListTableNamesByNamespaceResponse{}
}