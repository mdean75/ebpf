package nethealth

import "strings"

const StreamCorrIDHeaderKey = "x-stream-corr-id"

type GrpcStreamAssociationInterceptor struct {
	metadataRegistry *SocketMetadataRegistry
	headerKey        string
	metadataKey      string
}

func NewGrpcStreamAssociationInterceptor(registry *SocketMetadataRegistry) *GrpcStreamAssociationInterceptor {
	return NewGrpcStreamAssociationInterceptorWithConfig(registry, StreamCorrIDHeaderKey, "streamCorrID")
}

func NewGrpcStreamAssociationInterceptorWithConfig(registry *SocketMetadataRegistry, headerKey, metadataKey string) *GrpcStreamAssociationInterceptor {
	return &GrpcStreamAssociationInterceptor{
		metadataRegistry: registry,
		headerKey:        headerKey,
		metadataKey:      metadataKey,
	}
}

func (g *GrpcStreamAssociationInterceptor) BindStreamCorrelation(flow SocketFlow, streamCorrID string) {
	if strings.TrimSpace(streamCorrID) == "" {
		return
	}
	flowKey := flow.ToFlowKey()
	reverseFlowKey := flow.Reversed().ToFlowKey()

	g.metadataRegistry.PutForFlow(flowKey, g.metadataKey, streamCorrID)
	g.metadataRegistry.PutForFlow(reverseFlowKey, g.metadataKey, streamCorrID)
	g.metadataRegistry.AddStreamCorrIDForFlow(flowKey, streamCorrID)
	g.metadataRegistry.AddStreamCorrIDForFlow(reverseFlowKey, streamCorrID)
}

func (g *GrpcStreamAssociationInterceptor) InterceptCall(headers map[string]string, contextStreamCorrID string, flow SocketFlow) string {
	streamCorrID := FirstNonBlank(headers[g.headerKey], contextStreamCorrID)
	if streamCorrID == "" {
		return ""
	}
	g.BindStreamCorrelation(flow, streamCorrID)
	return streamCorrID
}

func FirstNonBlank(first, second string) string {
	if strings.TrimSpace(first) != "" {
		return first
	}
	if strings.TrimSpace(second) != "" {
		return second
	}
	return ""
}
