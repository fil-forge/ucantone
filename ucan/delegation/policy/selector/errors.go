package selector

import (
	"fmt"
	"strings"

	sdm "github.com/fil-forge/ucantone/ucan/delegation/policy/selector/datamodel"
)

const ResolutionErrorName = "ResolutionError"

func NewResolutionError(message string, at []string) sdm.ResolutionErrorModel {
	return sdm.ResolutionErrorModel{
		Name:    ResolutionErrorName,
		Message: fmt.Sprintf(`can not resolve path ".%s": %s`, strings.Join(at, "."), message),
		At:      at,
	}
}

const ParseErrorName = "ParseError"

func NewParseError(message string, source string, column int, token string) sdm.ParseErrorModel {
	return sdm.ParseErrorModel{
		Name:    ParseErrorName,
		Message: message,
		Source:  source,
		Column:  int64(column),
		Token:   token,
	}
}
