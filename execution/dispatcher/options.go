package dispatcher

import (
	"github.com/fil-forge/ucantone/validator"
)

// Option is an option configuring a UCAN executor.
type Option func(cfg *execConfig)

type execConfig struct {
	validationOpts    []validator.Option
	receiptTimestamps bool
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
