package main

import (
	"github.com/fil-forge/ucantone/examples/types"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/fieldgen"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func main() {
	if err := cbg.WriteMapEncodersToFile("../cbor_gen.go", "types",
		types.EmailsListArguments{},
		types.MessageSendArguments{},
		types.PromisedMsgSendArguments{},
		types.EchoArguments{},
	); err != nil {
		panic(err)
	}

	// Typed policy field descriptors for the same argument types, written to a
	// sibling package so the entry-point vars (e.g. fields.MessageSend) and the
	// descriptor types (e.g. fields.MessageSendArgumentsFields) don't collide
	// with the source types. PromisedMsgSendArguments is omitted: its
	// "await/ok" map key is not a valid jq selector segment.
	if err := fieldgen.WriteFieldDescriptors("../fields/policy_fields_gen.go", "fields",
		types.EmailsListArguments{},
		types.MessageSendArguments{},
		types.EchoArguments{},
	); err != nil {
		panic(err)
	}
}
