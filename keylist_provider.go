package keystash

import (
	"context"
	"fmt"
	"io/ioutil"

	"cloud.google.com/go/storage"

	"github.com/pkg/errors"
)

type KeyListProvider interface {
	GetKeyList(name string) (*KeyList, error)
}

func NewKeyListProvider(providerSpec string) (KeyListProvider, error) {
	provider, specs, err := parseSpecString(providerSpec)
	if err != nil {
		return nil, err
	}

	switch provider {
	case "gkms":
		projectID := specs[0]
		locationID := specs[1]
		bucketName := specs[2]
		bucketPath := specs[3]
		return NewGKMSKeyListProvider(projectID, locationID, bucketName, bucketPath)
	default:
		return nil, errors.Errorf("provider not implemented: %s", provider)
	}
}

// GKMSKeyListProvider is a Google KMS and Google Storage backed keylist provider
type GKMSKeyListProvider struct {
	// KMS project ID
	projectID string
	// KMS location
	locationID string
	// Storage bucket name
	bucketName string
	// Storage bucket path
	bucketPath string
}

// NewGKMSKeyListProvider returns a Google KMS backed key list provider
func NewGKMSKeyListProvider(projectID, locationID, bucketName, bucketPath string) (*GKMSKeyListProvider, error) {
	return &GKMSKeyListProvider{
		projectID:  projectID,
		locationID: locationID,
		bucketName: bucketName,
		bucketPath: bucketPath,
	}, nil
}

// GetKeyList returns a KeyList by name
func (p *GKMSKeyListProvider) GetKeyList(name string) (*KeyList, error) {
	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "NewGKMSKeyListProvider:NewClient")
	}

	dataKeyPath := fmt.Sprintf("%s/%s", p.bucketPath, name)
	bucketReader, err := client.Bucket(p.bucketName).Object(dataKeyPath).NewReader(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "NewGKMSKeyListProvider:Bucket:Object")
	}
	defer bucketReader.Close()

	cipherText, err := ioutil.ReadAll(bucketReader)
	if err != nil {
		return nil, errors.Wrap(err, "NewGKMSKeyListProvider:ReadAll")
	}

	kms := NewGKMS(p.projectID, p.locationID)
	plainBytes, err := kms.Decrypt(ctx, p.bucketPath, cipherText)
	if err != nil {
		return nil, errors.Wrap(err, "NewGKMSKeyListProvider:Decrypt")
	}

	keyList, err := KeyListFromJSON(string(plainBytes))
	return keyList, err
}

type MemKeyListProvider struct {
	// values are JSON strings
	keylistData map[string]string
}

func NewMemKeyListProvider(keylistData map[string]string) (*MemKeyListProvider, error) {
	return &MemKeyListProvider{
		keylistData: keylistData,
	}, nil
}

func (p *MemKeyListProvider) GetKeyList(name string) (*KeyList, error) {
	json, ok := p.keylistData[name]
	if !ok {
		return nil, errors.Errorf("cannot find keylist %s", name)
	}
	return KeyListFromJSON(json)
}
