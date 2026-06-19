package did

// https://www.w3.org/TR/cid-1.0/#Multikey
const MultikeyVerificationMethodType = "Multikey"

const (
	MultikeyPublicKeyMultibaseProp = "publicKeyMultibase"
	MultikeySecretKeyMultibaseProp = "secretKeyMultibase"
)

// https://www.w3.org/TR/cid-1.0/#JsonWebKey
const JsonWebKeyVerificationMethodType = "JsonWebKey"

const (
	JsonWebKeyPublicKeyJwkProp = "publicKeyJwk"
	JsonWebKeySecretKeyJwkProp = "secretKeyJwk"
)
