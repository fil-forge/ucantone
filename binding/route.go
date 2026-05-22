package binding

import "github.com/fil-forge/ucantone/server"

// NewRoute builds a [Route] from a command binding and its handler. The command
// and handler are taken from the same [binding.Binding], so they cannot diverge,
// and the handler's argument and result types are checked against the command's
// (Args and OK) at compile time.
func NewRoute[Args, OK CBORValue](cmd Binding[Args, OK], fn HandlerFunc[Args, OK]) server.Route {
	return server.Route{Command: cmd.Command, Handler: cmd.Handler(fn)}
}
