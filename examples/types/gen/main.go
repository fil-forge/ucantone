package main

import (
	"github.com/fil-forge/ucantone/examples/types"
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
}
