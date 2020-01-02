package keystash

import (
	"errors"
	"strings"
)

// parseSpecString parses a spec string in the form of:
//   <provider>://<value1>:<value2>:<value3>...
// and returns the provider string and the slice of string values.
func parseSpecString(specStr string) (string, []string, error) {
	if specStr == "" {
		return "", nil, errors.New("spec string is blank")
	}

	providerSpec := strings.Split(specStr, "://")
	// The provider is always required, so error out when there's no separator
	if len(providerSpec) < 2 {
		return "", nil, errors.New("spec string has no provider")
	}

	provider := providerSpec[0]
	// The provider string before the separator must not be blank
	if provider == "" {
		return "", nil, errors.New("spec string has no provider")
	}

	// An empty fields list is valid
	if providerSpec[1] == "" {
		return provider, []string{}, nil
	}

	fields := strings.Split(providerSpec[1], ":")

	return provider, fields, nil
}
