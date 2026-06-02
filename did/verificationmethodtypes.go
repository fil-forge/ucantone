package did

// https://www.w3.org/TR/cid-1.0/#Multikey
const MultikeyVerificationMethodType = "Multikey"

const (
	MultikeyPublicKeyMultibase = "publicKeyMultibase"
	MultikeySecretKeyMultibase = "secretKeyMultibase"
)

// https://www.w3.org/TR/cid-1.0/#JsonWebKey
const JsonWebKeyVerificationMethodType = "JsonWebKey"

const (
	JsonWebKeyPublicKeyJwk = "publicKeyJwk"
	JsonWebKeySecretKeyJwk = "secretKeyJwk"
)
