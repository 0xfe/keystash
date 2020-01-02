# keystash

This package implements a KMS abstraction layer for Go.

It currently supports [Google KMS](https://cloud.google.com/kms) and an in-memory key manager.

## Usage

### Google Cloud KMS

Use the spec `gkms://<project>:<location>` to create the client.

```go
kms, err := keystash.NewKMS("gkms://qubit-keys:global")
```

To encrypt or decrypt provide the keyring and key (as `<keyring>/<key>`) to `Encrypt` or `Decrypt`.

```go
// Encrypt the string "boo"
cipherText, err := kms.Encrypt(context.Background(), "dev/quid-server", []byte("boo"))

// Decrypt it back
plainText, err := kms.Decrypt(context.Background(), "dev/quid-server", cipherText)
```

### In memory KMS

This is a fake KMS usefule for testing. It doesn't actually store keys. It uses AES-128 (or -256) in Galois Counter Mode (GCM), which is what GKMS uses too.

Use the spec `memkms://` to create the client.

```go
kms, err := keystash.NewKMS("memkms://")
```

To encrypt or decrypt provide an AES key and a nonce (as `<key>/<nonce>`) to `Encrypt` or `Decrypt`.

```go
key := "6368616e676520746869732070617373776f726420746f206120736563726574"
nonce := make([]byte, 12)
if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
  t.Fatal(err)
}

keySpec := fmt.Sprintf("%s/%s", key, hex.EncodeToString(nonce))

// Encrypt the string "boo"
cipherText, err := kms.Encrypt(context.Background(), keySpec, []byte("boo"))

// Decrypt it back
plainText, err := kms.Decrypt(context.Background(), keySpec, cipherText)
```