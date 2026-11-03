package server

import (
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
)

// Route maps a command to the handler that executes it. A Route can be carried
// as a value — e.g. collected via dependency injection — and applied to a
// server later with [HTTPServer.HandleRoute]:
//
//	for _, r := range routes {
//		srv.HandleRoute(r)
//	}
type Route struct {
	// Command is the command the route serves.
	Command ucan.Command
	// Handler executes one invocation of the command per call. Nil for a route
	// built with [NewBatchRoute].
	Handler execution.HandlerFunc
	// BatchHandler executes every invocation of the command in a request with
	// one call, and takes precedence over Handler. Nil for a route built with
	// [NewRoute].
	BatchHandler execution.BatchHandlerFunc
}

// NewRoute builds a [Route] from a command and a handler.
func NewRoute(cmd ucan.Command, fn execution.HandlerFunc) Route {
	return Route{Command: cmd, Handler: fn}
}

// NewBatchRoute builds a [Route] from a command and a batch handler.
func NewBatchRoute(cmd ucan.Command, fn execution.BatchHandlerFunc) Route {
	return Route{Command: cmd, BatchHandler: fn}
}
