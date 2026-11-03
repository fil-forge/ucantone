package dispatcher

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/validator"
)

// Dispatcher executes UCAN invocations by dispatching them to registered
// handlers.
type Dispatcher struct {
	authority              ucan.Issuer
	handlers               map[ucan.Command]execution.HandlerFunc
	batchHandlers          map[ucan.Command]execution.BatchHandlerFunc
	validationOpts         []validator.Option
	receiptTimestamps      bool
	handlerErrorReceiptTTL time.Duration
	panicLogger            PanicLogger
	maxConcurrency         int
}

// New creates an invocation executor that executes UCAN invocations by
// dispatching them to registered handlers.
//
// The authority is the identity of the local authority, used to verify
// signatures of delegations signed by it and sign receipts for executed tasks.
func New(authority ucan.Issuer, options ...Option) *Dispatcher {
	cfg := execConfig{
		handlerErrorReceiptTTL: DefaultHandlerErrorReceiptTTL,
		panicLogger:            logPanic,
		maxConcurrency:         DefaultMaxConcurrency,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	return &Dispatcher{
		authority:              authority,
		handlers:               map[ucan.Command]execution.HandlerFunc{},
		batchHandlers:          map[ucan.Command]execution.BatchHandlerFunc{},
		validationOpts:         cfg.validationOpts,
		receiptTimestamps:      cfg.receiptTimestamps,
		handlerErrorReceiptTTL: cfg.handlerErrorReceiptTTL,
		panicLogger:            cfg.panicLogger,
		maxConcurrency:         cfg.maxConcurrency,
	}
}

// Handle registers the handler that executes invocations of command, one call
// per invocation. A batch handler registered for the same command with
// [Dispatcher.HandleBatch] takes precedence over it. A nil handler panics.
func (d *Dispatcher) Handle(command ucan.Command, fn execution.HandlerFunc) {
	if fn == nil {
		panic(fmt.Sprintf("dispatcher.Handle: nil handler for %q", command))
	}
	d.handlers[command] = fn
}

// HandleBatch registers the handler that executes every invocation of command
// in a call to [Dispatcher.ExecuteAll] at once. It is always used for the
// command when registered, even for a single invocation passed to
// [Dispatcher.Execute], and takes precedence over a handler registered with
// [Dispatcher.Handle]. A nil handler panics.
func (d *Dispatcher) HandleBatch(command ucan.Command, fn execution.BatchHandlerFunc) {
	if fn == nil {
		panic(fmt.Sprintf("dispatcher.HandleBatch: nil batch handler for %q", command))
	}
	d.batchHandlers[command] = fn
}

// Execute validates the invocation and runs the handler registered for its
// command. When the command has a batch handler, the invocation runs through it
// as a batch of one. A panic anywhere along the way, in the handler or in
// validation code such as a DID resolver or verifier factory, fails that task
// with a short-lived [execution.ExecutionFailureErrorName] receipt instead of
// escaping to the caller, so one misbehaving invocation cannot take down a
// server that executes many at once. The receipt does not say that the
// failure was a panic; the panic value goes to the configured [PanicLogger].
func (d *Dispatcher) Execute(req execution.Request) (execution.Response, error) {
	if _, ok := d.batchHandlers[req.Invocation().Command()]; ok {
		resps, err := d.ExecuteAll([]execution.Request{req})
		if err != nil {
			return nil, err
		}
		return resps[0], nil
	}
	return d.guard(req, func() (execution.Response, error) {
		return d.execute(req)
	})
}

// ExecuteAll executes the requests and returns their responses in request
// order. Requests for a command with a batch handler are validated one by one
// and the valid ones go to the batch handler in a single call per command; the
// invalid ones get their failure receipts and never reach it. Requests for any
// other command execute as [Dispatcher.Execute] runs them.
//
// Validations and handler calls run concurrently, each on its own goroutine,
// with at most [WithMaxConcurrency] of them running at once. A batch handler
// call takes one slot, and starts once every invocation of its command has been
// validated. Panics are recovered as [Dispatcher.Execute] recovers them: a
// panic in a batch handler fails every task of the batch that does not already
// have a failure.
func (d *Dispatcher) ExecuteAll(reqs []execution.Request) ([]execution.Response, error) {
	resps := make([]execution.Response, len(reqs))
	errs := make([]error, len(reqs))
	// ready[i] says resps[i] awaits its batch handler. Each goroutine writes
	// only its own slots, so the slices need no lock.
	ready := make([]bool, len(reqs))

	var slots chan struct{}
	if d.maxConcurrency > 0 {
		slots = make(chan struct{}, d.maxConcurrency)
	}
	acquire := func() {
		if slots != nil {
			slots <- struct{}{}
		}
	}
	release := func() {
		if slots != nil {
			<-slots
		}
	}

	type batchGroup struct {
		handler   execution.BatchHandlerFunc
		members   []int
		validated sync.WaitGroup
	}
	// group[i] is the batch request i belongs to, or nil when its command has
	// no batch handler.
	group := make([]*batchGroup, len(reqs))
	groups := map[ucan.Command]*batchGroup{}
	var order []ucan.Command
	for i, req := range reqs {
		cmd := req.Invocation().Command()
		fn, ok := d.batchHandlers[cmd]
		if !ok {
			continue
		}
		g, ok := groups[cmd]
		if !ok {
			g = &batchGroup{handler: fn}
			groups[cmd] = g
			order = append(order, cmd)
		}
		g.members = append(g.members, i)
		group[i] = g
	}

	var wg sync.WaitGroup
	// Each batch runner starts before any request is admitted, so it competes
	// for a slot as soon as its own validations finish rather than after the
	// whole request has been admitted. It holds no slot while it waits, so it
	// cannot starve the validations of the slots they need.
	for _, cmd := range order {
		g := groups[cmd]
		g.validated.Add(len(g.members))
		wg.Go(func() {
			g.validated.Wait()
			var members []int
			for _, i := range g.members {
				if ready[i] {
					members = append(members, i)
				}
			}
			if len(members) == 0 {
				return
			}
			acquire()
			defer release()
			d.runBatch(cmd, g.handler, reqs, resps, errs, members)
		})
	}

	for i, req := range reqs {
		// Acquire before spawning, so a request larger than the cap waits in
		// this loop instead of as a pile of blocked goroutines.
		acquire()
		g := group[i]
		if g == nil {
			wg.Go(func() {
				defer release()
				resps[i], errs[i] = d.guard(req, func() (execution.Response, error) {
					return d.execute(req)
				})
			})
			continue
		}
		// The runner waiting on the group is what wg tracks for this request.
		go func() {
			defer g.validated.Done()
			defer release()
			resps[i], errs[i] = d.guard(req, func() (execution.Response, error) {
				res, ok, err := d.prepare(req)
				ready[i] = ok
				return res, err
			})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			errs[i] = fmt.Errorf("executing task %s: %w", reqs[i].Invocation().Task().Link(), err)
		}
	}
	return resps, errors.Join(errs...)
}

// runBatch calls the batch handler with the given members of reqs and resps.
// When the handler returns an error or panics, every task without a failure
// receipt gets a transient failure; a task that already has one keeps it. A
// task left without a receipt fails either way.
func (d *Dispatcher) runBatch(cmd ucan.Command, fn execution.BatchHandlerFunc, reqs []execution.Request, resps []execution.Response, errs []error, members []int) {
	// The handler gets its own slice of its own structs, so whatever it does
	// to them leaves the dispatcher's record of the responses intact.
	items := make([]execution.Batch, len(members))
	for j, i := range members {
		items[j] = execution.Batch{Request: reqs[i], Response: resps[i]}
	}

	var failure error
	func() {
		// See guard for why a flag rather than the recovered value.
		returned := false
		defer func() {
			if returned {
				return
			}
			d.panicLogger(reqs[members[0]], recover())
			failure = execution.NewExecutionFailureError(cmd)
		}()
		if err := fn(items); err != nil {
			failure = execution.NewHandlerExecutionError(cmd, err)
		}
		returned = true
	}()

	for _, i := range members {
		rcpt := resps[i].Receipt()
		switch {
		case rcpt == nil:
			missing := failure
			if missing == nil {
				missing = execution.NewExecutionFailureError(cmd)
			}
			resps[i], errs[i] = d.transientFailure(reqs[i], missing)
		case failure != nil && !rcpt.Out().IsErr():
			// A failure the task already has stays: it is a specific answer
			// (from the handler, a middleware or argument decoding) that the
			// batch failing does not change. A success does not survive it,
			// since the work may not have completed.
			resps[i], errs[i] = d.transientFailure(reqs[i], failure)
		}
	}
}

// guard runs f, turning a panic into a short-lived
// [execution.ExecutionFailureErrorName] receipt for req after recording it.
func (d *Dispatcher) guard(req execution.Request, f func() (execution.Response, error)) (res execution.Response, err error) {
	// recover() alone cannot tell a normal return from panic(nil), which is
	// recovered as nil under GODEBUG=panicnil=1, so the flag is what says
	// whether f returned.
	returned := false
	defer func() {
		if returned {
			return
		}
		d.panicLogger(req, recover())
		res, err = d.transientFailure(req, execution.NewExecutionFailureError(req.Invocation().Command()))
	}()
	res, err = f()
	returned = true
	return res, err
}

// execute runs a request through validation and its per-invocation handler,
// without the recovery boundary.
func (d *Dispatcher) execute(req execution.Request) (execution.Response, error) {
	res, ok, err := d.prepare(req)
	if !ok || err != nil {
		return res, err
	}
	cmd := req.Invocation().Command()
	err = d.handlers[cmd](req, res)
	if err != nil {
		return d.transientFailure(req, execution.NewHandlerExecutionError(cmd, err))
	}
	return res, nil
}

// prepare checks the audience, finds a handler and validates the invocation.
// When ok it returns an empty response for the handler to complete; otherwise
// the response already holds the failure receipt.
func (d *Dispatcher) prepare(req execution.Request) (res execution.Response, ok bool, err error) {
	aud := req.Invocation().Audience()
	if !aud.Defined() {
		aud = req.Invocation().Subject()
	}
	if aud != d.authority.DID() {
		res, err := execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(execution.NewInvalidAudienceError(d.authority.DID(), aud)),
		)
		return res, false, err
	}

	cmd := req.Invocation().Command()
	_, single := d.handlers[cmd]
	_, batch := d.batchHandlers[cmd]
	if !single && !batch {
		res, err := execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(NewHandlerNotFoundError(cmd)),
		)
		return res, false, err
	}

	opts := []validator.Option{validator.WithMetadata(req.Metadata())}
	opts = append(opts, d.validationOpts...)
	if req.Metadata() != nil {
		opts = append(opts, validator.WithProofResolver(validator.ProofsFromContainer(req.Metadata())))
	}

	err = validator.ValidateInvocation(
		req.Context(),
		req.Invocation(),
		opts...,
	)
	if err != nil {
		res, err := execution.NewResponse(
			req.Invocation().Task().Link(),
			execution.WithIssuer(d.authority),
			execution.WithReceiptTimestamp(d.receiptTimestamps),
			execution.WithFailure(err),
		)
		return res, false, err
	}

	res, err = execution.NewResponse(
		req.Invocation().Task().Link(),
		execution.WithIssuer(d.authority),
		execution.WithReceiptTimestamp(d.receiptTimestamps),
	)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create response: %w", err)
	}
	return res, true, nil
}

// transientFailure builds the response for a failure that is unexpected and
// likely transient: an error returned from a handler or a recovered panic. The
// receipt asserting it is short-lived, so clients retry rather than cache it.
// Permanent errors are set as error results on the response by the handler.
func (d *Dispatcher) transientFailure(req execution.Request, failure error) (execution.Response, error) {
	respOpts := []execution.ResponseOption{
		execution.WithIssuer(d.authority),
		execution.WithReceiptTimestamp(d.receiptTimestamps),
	}
	if d.handlerErrorReceiptTTL > 0 {
		exp := ucan.Now() + ucan.UnixTimestamp(d.handlerErrorReceiptTTL.Seconds())
		respOpts = append(respOpts, execution.WithReceiptExpiration(exp))
	}
	respOpts = append(respOpts, execution.WithFailure(failure))
	return execution.NewResponse(req.Invocation().Task().Link(), respOpts...)
}

// logPanic is the default [PanicLogger]. It prints the panic and the stack
// through the standard log package, the way net/http reports the panics it
// recovers, so it adds no dependency to a binary that serves HTTP.
func logPanic(req execution.Request, value any) {
	buf := make([]byte, panicStackSize)
	buf = buf[:runtime.Stack(buf, false)]
	log.Printf("panic executing %s task %s: %v\n%s",
		req.Invocation().Command(), req.Invocation().Task().Link(), value, buf)
}

// panicStackSize matches the buffer net/http uses for the same purpose.
const panicStackSize = 64 << 10
