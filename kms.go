package keystash

import (
	"context"

	"github.com/pkg/errors"
)

type KMSBase struct {
	backend string
}

type KMS interface {
	Encrypt(ctx context.Context, keySpec string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, keySpec string, cipherText []byte) ([]byte, error)
}

func NewKMS(spec string) (KMS, error) {
	provider, fields, err := parseSpecString(spec)
	if err != nil {
		return nil, errors.Wrap(err, "NewKMSFromSpec")
	}

	switch provider {
	case "gkms":
		if len(fields) < 2 {
			return nil, errors.Errorf("invalid GKMS spec: %v (expecting gkms://<project>:<location>)", spec)
		}
		return NewGKMS(fields[0], fields[1]), nil
	case "memkms":
		return NewMemKMS(), nil
	default:
		return nil, errors.Errorf("invalid KMS spec: %v", spec)
	}
}
