package server

import (
	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
)

// Route maps a command to the handler that executes it. A Route can be carried
// as a value — e.g. collected via dependency injection — and applied to a
// server later with [HTTPServer.Handle]:
//
//	for _, r := range routes {
//		srv.Handle(r.Command, r.Handler)
//	}
type Route struct {
	Command ucan.Command
	Handler execution.HandlerFunc
}

// NewRoute builds a [Route] from a command and a handler.
func NewRoute(cmd ucan.Command, fn execution.HandlerFunc) Route {
	return Route{Command: cmd, Handler: fn}
}
