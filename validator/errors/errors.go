package errors

import (
	"fmt"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/did"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
	"github.com/fil-forge/ucantone/ucan"
)

const UnavailableProofErrorName = "UnavailableProof"

func NewUnavailableProofError(p ucan.Link, cause error) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: UnavailableProofErrorName,
		Message:   fmt.Sprintf("linked proof %q could not be resolved: %s", p, cause.Error()),
	}
}

const DIDKeyResolutionErrorName = "DIDKeyResolutionError"

func NewDIDKeyResolutionError(d did.DID, cause error) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: DIDKeyResolutionErrorName,
		Message:   fmt.Sprintf("unable to resolve %q key: %s", d, cause.Error()),
	}
}

const ExpiredErrorName = "Expired"

func NewExpiredError(t ucan.Token) edm.ErrorModel {
	var name string
	if _, ok := t.(ucan.Invocation); ok {
		name = "invocation"
	} else {
		name = "proof"
	}
	return edm.ErrorModel{
		ErrorName: ExpiredErrorName,
		Message:   fmt.Sprintf("%s %q has expired on %s", name, t.Link(), time.Unix(int64(*t.Expiration()), 0).Format(time.RFC3339)),
	}
}

const TooEarlyErrorName = "TooEarly"

func NewTooEarlyError(t ucan.Delegation) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: TooEarlyErrorName,
		Message:   fmt.Sprintf("proof %q is not valid before %s", t.Link(), time.Unix(int64(*t.NotBefore()), 0).Format(time.RFC3339)),
	}
}

const InvalidSignatureErrorName = "InvalidSignature"

func NewInvalidSignatureError(token ucan.Token, verifier ucan.Verifier) edm.ErrorModel {
	issuer := token.Issuer().DID()
	key := verifier.DID()
	var message string
	if strings.HasPrefix(issuer.String(), "did:key") {
		message = fmt.Sprintf(`proof %s does not have a valid signature from %s`, token.Link(), key)
	} else {
		message = strings.Join([]string{
			fmt.Sprintf("proof %q issued by %q does not have a valid signature from %q", token.Link(), issuer, key),
			"  ℹ️ Issuer probably signed with a different key, which got rotated, invalidating delegations that were issued with prior keys",
		}, "\n")
	}
	return edm.ErrorModel{
		ErrorName: InvalidSignatureErrorName,
		Message:   message,
	}
}

const UnverifiableSignatureErrorName = "UnverifiableSignature"

func NewUnverifiableSignatureError(token ucan.Token, cause error) edm.ErrorModel {
	issuer := token.Issuer().DID()
	return edm.ErrorModel{
		ErrorName: UnverifiableSignatureErrorName,
		Message:   fmt.Sprintf("proof %q issued by %q cannot be verified: %s", token.Link(), issuer, cause.Error()),
	}
}

const PrincipalAlignmentErrorName = "InvalidAudience"

func NewPrincipalAlignmentError(audience ucan.Principal, dlg ucan.Delegation) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: PrincipalAlignmentErrorName,
		Message:   fmt.Sprintf("delegation %q audience is %q not %q", dlg.Link(), audience.DID(), dlg.Audience().DID()),
	}
}

const SubjectAlignmentErrorName = "InvalidSubject"

func NewSubjectAlignmentError(subject ucan.Subject, t ucan.Token) edm.ErrorModel {
	var name string
	if _, ok := t.(ucan.Invocation); ok {
		name = "invocation"
	} else {
		name = "delegation"
	}
	return edm.ErrorModel{
		ErrorName: SubjectAlignmentErrorName,
		Message:   fmt.Sprintf("%s %q subject is %q not %q", name, t.Link(), t.Subject().DID(), subject.DID()),
	}
}

const MalformedArgumentsErrorName = "MalformedArguments"

func NewMalformedArgumentsError(cmd ucan.Command, cause error) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: MalformedArgumentsErrorName,
		Message:   fmt.Sprintf("malformed arguments for command %q: %s", cmd, cause.Error()),
	}
}

const InvalidClaimErrorName = "InvalidClaim"

func NewInvalidClaimError(msg string) edm.ErrorModel {
	return edm.ErrorModel{
		ErrorName: InvalidClaimErrorName,
		Message:   msg,
	}
}
