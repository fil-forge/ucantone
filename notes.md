# Implementation notes

## General

* Switched to more Go idiomatic style where we accept interfaces and return concrete types.
* No IPLD prime - [CBOR gen](https://github.com/whyrusleeping/cbor-gen) is adequate and significantly less complicated. It's a shame to not have IPLD schemas, but the inflexibility and boilerplate it introduces is prohibitive.
* Consequently, no `ipld.Link` usage. The `cid.Cid` type is actually useful, despite it being a bit heavy. We _have_ to use it anyways, since it's the only thing that implements `ipld.Link`. Also `Link` is just such a nothing interface.
* Fewer generics. Generic types in Go are not super powerful and can easily get in the way. We use generics more sparingly in this version.
* DAG-JSON all the things to make debugging easier!

## Specifics

* `DID` is now in string representation (not their binary representation as a string). You can call `Encode` and `Decode` to move to/from binary. Note, it does not have a `Bytes()` method since encoding to bytes may raise an error - you must use `Encode` instead.
* Receipt is not defined properly in the specs...
* Signatures
  * Varsig does not implement anything other than ed25519/secp256k1 signature and dag-cbor payload right now.
  * Signatures are now just raw bytes - no multibase prefix since signature info is all communicated in varsig header.
* Principal
    * No RSA principal implementation.
    * Signer moved from `principal/<type>/signer` to `principal/<type>` for ease of use.
    * Renamed `Encode()` method on `Signer` and `Verifier` to `Bytes()`, since it just returns the (multibase prefixed) bytes.
    * Ed25519 signer byte representation is now just the multiformats tagged private key bytes. Go internally uses 64 bytes for the private key which redundantly includes the public key.
* Containers hold at most `container.MaxTokens` (8192) tokens. The container spec sets no limit; this is the cbor-gen/dag-json-gen array limit, pinned with a `maxlen` struct tag on `ContainerModel.Ctn1` so a generator upgrade cannot move it silently. The exported constant lets callers budget before encoding.
* Server is a HTTP `RoundTripper`
* A panic while executing an invocation fails its own task: `Dispatcher.Execute` recovers it and issues a short-lived `ExecutionFailure` receipt, with the same TTL a returned handler error gets. The boundary is the whole of `Execute` because validation runs application code too (a `WithDIDResolver`, a `WithVerifierFactories` factory, a nonstandard-signature verifier), and a panic there would otherwise escape the worker goroutine the server runs each invocation on. There is one receipt for every panic, and it does not say that a panic happened, let alone where: a client cannot act on the distinction, and a developer debugging it needs the log line anyway, since the panic value never reaches the client (it was not written for one and can carry internals). The value goes to a `PanicLogger` callback (`WithPanicLogger` on the dispatcher and the server); the default prints it with the stack through the standard `log` package and `runtime.Stack`, as net/http does, so the library links neither `log/slog` nor `runtime/debug` into a consumer binary. Before this, a panic escaped to net/http, which dropped the connection with no receipt; with invocations executing on their own goroutines it would have crashed the process.
* The server executes the invocations of one request concurrently, one goroutine each, admitted through a per-request semaphore (`server.WithMaxConcurrency`, default 100, zero for no cap). This is what every Go server surveyed does for streams on a connection (grpc-go, x/net/http2, quic-go, go-libp2p): goroutine per unit, a semaphore or queue in front. The cap is per request rather than server-wide because that is the HTTP/2 analogue and because a process-wide bound belongs at the listener (`netutil.LimitListener`, `HTTP2Config.MaxConcurrentStreams`), where the Go team put it when asked for one in net/http (golang/go#6012). The default of 100 matches quic-go and the RFC 9113 floor; x/net/http2 uses 250 and grpc-go none. Receipts are merged in request order after every invocation has finished, so the response does not depend on which handler finished first.
