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
	maxConcurrency         int
}

// DefaultMaxConcurrency is how many validations and per-invocation handler
// calls of one [Dispatcher.ExecuteAll] call run at the same time unless
// [WithMaxConcurrency] says otherwise.
const DefaultMaxConcurrency = 100

// WithMaxConcurrency caps how many validations and per-invocation handler
// calls (those of a handler registered with [Dispatcher.Handle] or wrapped by
// [Each]) of one [Dispatcher.ExecuteAll] call run at the same time. A batch
// handler call does not count: it is one goroutine per command. The cap applies
// to each call alone: concurrent calls each get their own.
//
// - WithMaxConcurrency(1) runs them serially, one after another.
// - WithMaxConcurrency(0) removes the cap.
// - A negative value panics.
//
// Defaults to [DefaultMaxConcurrency].
func WithMaxConcurrency(n int) Option {
	if n < 0 {
		panic("dispatcher.WithMaxConcurrency: n must not be negative")
	}
	return func(cfg *execConfig) {
		cfg.maxConcurrency = n
	}
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
// decided the outcome by then: the task fails with the receipt
// [execution.NewExecutionFailureError] builds, which does not reveal the panic.
// The logger runs on the panicking goroutine inside the deferred recover, so
// [runtime.Stack] or [runtime/debug.Stack] called from it returns the stack of
// the panic.
type PanicLogger func(req execution.Request, value any)

// WithPanicLogger sets the function that records recovered panics.
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
