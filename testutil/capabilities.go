package testutil

import (
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/validator/capability"
)

// logs a message to the console
var ConsoleLogCapability, _ = capability.New(
	"/console/log",
	capability.WithPolicyBuilder(policy.NotEqual(".message", "")),
)

// echos the arguments back to the caller
var TestEchoCapability, _ = capability.New("/test/echo")
