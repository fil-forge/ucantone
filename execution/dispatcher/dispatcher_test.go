package dispatcher_test

import (
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/execution"
	"github.com/fil-forge/ucantone/execution/dispatcher"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/result"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/invocation"
	verrs "github.com/fil-forge/ucantone/validator/errors"
	"github.com/stretchr/testify/require"
)

func TestDispatcher(t *testing.T) {
	service := testutil.RandomSigner(t)
	alice := testutil.RandomSigner(t)

	t.Run("dispatches invocations for execution", func(t *testing.T) {
		executor := dispatcher.New(service)

		var messages []ipld.Any
		executor.Handle(testutil.ConsoleLogCapability, func(req execution.Request, res execution.Response) error {
			msg := testutil.ArgsMap(t, req.Invocation())["message"]
			t.Log(msg)
			messages = append(messages, msg)
			return res.SetSuccess(datamodel.Map{})
		})
		executor.Handle(testutil.TestEchoCapability, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		logInv, err := testutil.ConsoleLogCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "Hello, World!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		resp, err := executor.Execute(execution.NewRequest(t.Context(), logInv))
		require.NoError(t, err)

		_, x := result.Unwrap(resp.Receipt().Out())
		require.Nil(t, x)

		require.Len(t, messages, 1)
		require.Equal(t, "Hello, World!", messages[0])

		echoInv, err := testutil.TestEchoCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		resp, err = executor.Execute(execution.NewRequest(t.Context(), echoInv))
		require.NoError(t, err)

		o, x := result.Unwrap(resp.Receipt().Out())
		require.NotNil(t, o)
		require.Nil(t, x)
		t.Log(o)

		require.Len(t, messages, 1) // should not have changed
		require.Equal(t, "echo!", testutil.ResultMap(t, o)["message"])
	})

	t.Run("handler not found", func(t *testing.T) {
		executor := dispatcher.New(service)

		inv, err := testutil.TestEchoCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		o, x := result.Unwrap(resp.Receipt().Out())
		require.Nil(t, o)
		require.NotNil(t, x)
		t.Log(x)

		require.Equal(t, dispatcher.HandlerNotFoundErrorName, testutil.ResultMap(t, x)["name"])
	})

	t.Run("invalid audience", func(t *testing.T) {
		executor := dispatcher.New(service)

		inv, err := testutil.TestEchoCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "echo!"},
			invocation.WithAudience(alice),
		)
		require.NoError(t, err)

		resp, err := executor.Execute(execution.NewRequest(t.Context(), inv))
		require.NoError(t, err)

		o, x := result.Unwrap(resp.Receipt().Out())
		require.Nil(t, o)
		require.NotNil(t, x)
		t.Log(x)

		require.Equal(t, execution.InvalidAudienceErrorName, testutil.ResultMap(t, x)["name"])
	})

	t.Run("handler execution error", func(t *testing.T) {
		executor := dispatcher.New(service)

		executor.Handle(testutil.ConsoleLogCapability, func(req execution.Request, res execution.Response) error {
			return fmt.Errorf("boom")
		})

		logInv, err := testutil.ConsoleLogCapability.Invoke(
			alice,
			alice,
			datamodel.Map{"message": "Hello, World!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		resp, err := executor.Execute(execution.NewRequest(t.Context(), logInv))
		require.NoError(t, err)

		o, x := result.Unwrap(resp.Receipt().Out())
		require.Nil(t, o)
		require.NotNil(t, x)
		t.Log(x)

		require.Equal(t, execution.HandlerExecutionErrorName, testutil.ResultMap(t, x)["name"])
	})

	t.Run("validation error", func(t *testing.T) {
		executor := dispatcher.New(service)
		executor.Handle(testutil.TestEchoCapability, func(req execution.Request, res execution.Response) error {
			return res.SetSuccess(testutil.ArgsMap(t, req.Invocation()))
		})

		logInv, err := testutil.TestEchoCapability.Invoke(
			alice,
			testutil.RandomDID(t), // alice has no authority to invoke with this subject
			datamodel.Map{"message": "Hello, World!"},
			invocation.WithAudience(service),
		)
		require.NoError(t, err)

		resp, err := executor.Execute(execution.NewRequest(t.Context(), logInv))
		require.NoError(t, err)

		o, x := result.Unwrap(resp.Receipt().Out())
		require.Nil(t, o)
		require.NotNil(t, x)
		t.Log(x)

		require.Equal(t, verrs.InvalidClaimErrorName, testutil.ResultMap(t, x)["name"])
	})
}
