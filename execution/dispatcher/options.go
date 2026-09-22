package dispatcher

import (
	"time"

	"github.com/fil-forge/ucantone/execution"

	"github.com/fil-forge/ucantone/validator"
)

// DefaultHandlerErrorReceiptTTL is the default TTL for receipts issued when a
// handler returns an error. Errors returned from handlers are unexpected and
// likely transient (permanent errors are set as error results on the
// response), so their receipts are short-lived assertions.
const DefaultHandlerErrorReceiptTTL = 30 * time.Second

// Option is an option configuring a UCAN executor.
type Option func(cfg *execConfig)

type execConfig struct {
	validationOpts         []validator.Option
	receiptTimestamps      bool
	handlerErrorReceiptTTL time.Duration
	panicLogger            PanicLogger
}

func WithValidationOptions(options ...validator.Option) Option {
	return func(cfg *execConfig) {
		cfg.validationOpts = append(cfg.validationOpts, options...)
	}
}

// WithReceiptTimestamps configures the dispatcher to issue receipts with
// issuance timestamps or not.
func WithReceiptTimestamps(enabled bool) Option {
	return func(cfg *execConfig) {
		cfg.receiptTimestamps = enabled
	}
}

// WithHandlerErrorReceiptTTL configures the TTL for receipts issued when a
// handler returns an error. A zero or negative value disables the expiration,
// making the receipt a permanent assertion. Defaults to
// [DefaultHandlerErrorReceiptTTL].
func WithHandlerErrorReceiptTTL(ttl time.Duration) Option {
	return func(cfg *execConfig) {
		cfg.handlerErrorReceiptTTL = ttl
	}
}

// PanicLogger is called with the request and the recovered value when
// executing an invocation panics, whether in the handler or in validation code
// such as a DID resolver or verifier factory. The dispatcher has already
// decided the outcome by then: a handler panic fails the task with the receipt
// [execution.NewHandlerExecutionError] builds, whose message says only that the
// handler panicked, and any other panic with the one
// [execution.NewExecutionPanicError] builds. The logger runs on the panicking
// goroutine inside the deferred recover, so [runtime.Stack] or
// [runtime/debug.Stack] called from it returns the stack of the panic.
type PanicLogger func(req execution.Request, value any)

// WithPanicLogger sets the function that reports recovered panics.
// The default prints the command, task, panic value and stack through the
// standard log package. Set it to route panics to another logger or an error
// tracker. A nil logger panics.
func WithPanicLogger(logger PanicLogger) Option {
	if logger == nil {
		panic("dispatcher.WithPanicLogger: logger must not be nil")
	}
	return func(cfg *execConfig) {
		cfg.panicLogger = logger
	}
}
