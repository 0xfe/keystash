package keystash

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2/google"
	cloudkms "google.golang.org/api/cloudkms/v1"
)

type GKMS struct {
	*KMSBase
	projectID  string
	locationID string
}

func NewGKMS(projectID, locationID string) *GKMS {
	return &GKMS{
		KMSBase:    &KMSBase{"gkms"},
		projectID:  projectID,
		locationID: locationID,
	}
}

func (gkms *GKMS) Decrypt(ctx context.Context, keySpec string, ciphertext []byte) ([]byte, error) {
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)

	if err != nil {
		return nil, errors.Wrap(err, "GKMS:Decrypt")
	}

	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, errors.Wrap(err, "GKMS:Decrypt")
	}

	parts := strings.Split(keySpec, "/")
	if len(parts) < 2 {
		return nil, errors.Errorf("expecting keySpec <keyring>/<key>, got: %v", keySpec)
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		gkms.projectID, gkms.locationID, parts[0], parts[1])

	logrus.Debugf("decrypting with key: %s", parentName)
	req := &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, req).Do()
	if err != nil {
		return nil, errors.Wrap(err, "GKMS:Decrypt")
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

func (gkms *GKMS) Encrypt(ctx context.Context, keySpec string, plaintext []byte) ([]byte, error) {
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, errors.Wrap(err, "GKMS:Encrypt")
	}

	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, errors.Wrap(err, "GKMS:Encrypt")
	}

	parts := strings.Split(keySpec, "/")
	if len(parts) < 2 {
		return nil, errors.Errorf("expecting keySpec <keyring>/<key>, got: %v", keySpec)
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		gkms.projectID, gkms.locationID, parts[0], parts[1])

	logrus.Debugf("encrypting with key: %s", parentName)
	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, req).Do()
	if err != nil {
		return nil, errors.Wrap(err, "GKMS:Encrypt")
	}

	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}
