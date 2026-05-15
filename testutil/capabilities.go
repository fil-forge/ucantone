package testutil

import "github.com/fil-forge/ucantone/ucan/command"

// logs a message to the console
var ConsoleLogCommand, _ = command.Parse("/console/log")

// echos the arguments back to the caller
var TestEchoCommand, _ = command.Parse("/test/echo")
