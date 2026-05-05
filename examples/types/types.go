package types

import "github.com/fil-forge/ucantone/ucan/promise"

type MessageSendArguments struct {
	To      []string `cborgen:"to"`
	Subject string   `cborgen:"subject"`
	Message string   `cborgen:"message"`
}

type PromisedMsgSendArguments struct {
	From    string          `cborgen:"from"`
	To      promise.AwaitOK `cborgen:"to"`
	Message string          `cborgen:"message"`
}

type EmailsListArguments struct {
	Limit uint64 `cborgen:"limit"`
}

type EchoArguments struct {
	Message string `cborgen:"message"`
}
