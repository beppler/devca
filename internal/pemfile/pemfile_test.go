package pemfile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type equaler interface {
	Equal(crypto.PrivateKey) bool
}

func newTestCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSaveLoadRoundTrip(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  crypto.Signer
	}{
		{"ecdsa", newECKey(t)},
		{"rsa", rsaKey},
		{"ed25519", ed25519Key},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newTestCertificate(t, tt.key)
			dir := t.TempDir()
			certPath := filepath.Join(dir, "cert.pem")
			keyPath := filepath.Join(dir, "key.pem")

			if err := Save(cert, certPath, tt.key, keyPath); err != nil {
				t.Fatal(err)
			}

			gotCert, gotKey, err := Load(certPath, keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if !gotCert.Equal(cert) {
				t.Error("loaded certificate differs from saved one")
			}
			if !tt.key.(equaler).Equal(gotKey) {
				t.Error("loaded private key differs from saved one")
			}

			keyPEM, err := os.ReadFile(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if block, _ := pem.Decode(keyPEM); block == nil || block.Type != "PRIVATE KEY" {
				t.Errorf("private key is not saved as PKCS#8 PEM")
			}
		})
	}
}

func TestSaveFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions are not supported on Windows")
	}

	key := newECKey(t)
	cert := newTestCertificate(t, key)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// An existing, world-readable key file must be tightened on overwrite.
	if err := os.WriteFile(keyPath, nil, 0644); err != nil {
		t.Fatal(err)
	}

	if err := Save(cert, certPath, key, keyPath); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0600 {
		t.Errorf("private key mode = %o, want 600", mode)
	}

	info, err = os.Stat(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0137 != 0 {
		t.Errorf("certificate mode = %o, want at most 640", mode)
	}
}

func TestSaveErrors(t *testing.T) {
	key := newECKey(t)
	cert := newTestCertificate(t, key)
	dir := t.TempDir()
	missingDir := filepath.Join(dir, "missing")

	tests := []struct {
		name     string
		key      crypto.PrivateKey
		certPath string
		keyPath  string
	}{
		{"unsupported key", struct{}{}, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")},
		{"certificate not writable", key, filepath.Join(missingDir, "cert.pem"), filepath.Join(dir, "key.pem")},
		{"key not writable", key, filepath.Join(dir, "cert.pem"), filepath.Join(missingDir, "key.pem")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Save(cert, tt.certPath, tt.key, tt.keyPath); err == nil {
				t.Error("want error")
			}
		})
	}
}

func TestLoadLegacyKeyFormats(t *testing.T) {
	ecKey := newECKey(t)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		key   crypto.Signer
		block *pem.Block
	}{
		{"EC PRIVATE KEY", ecKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}},
		{"RSA PRIVATE KEY", rsaKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newTestCertificate(t, tt.key)
			certPath := writeFile(t, "cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			keyPath := writeFile(t, "key.pem", pem.EncodeToMemory(tt.block))

			_, gotKey, err := Load(certPath, keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.key.(equaler).Equal(gotKey) {
				t.Error("loaded private key differs from original")
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	key := newECKey(t)
	cert := newTestCertificate(t, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	validCert := writeFile(t, "cert.pem", certPEM)
	validKey := writeFile(t, "key.pem", keyPEM)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	notPEM := writeFile(t, "not.pem", []byte("not a PEM file"))
	garbage := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})

	tests := []struct {
		name     string
		certPath string
		keyPath  string
	}{
		{"missing certificate", missing, validKey},
		{"certificate not PEM", notPEM, validKey},
		{"invalid certificate", writeFile(t, "bad-cert.pem", garbage), validKey},
		{"missing key", validCert, missing},
		{"key not PEM", validCert, notPEM},
		{"unsupported key type", validCert, writeFile(t, "dsa.pem", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: keyDER}))},
		{"invalid key", validCert, writeFile(t, "bad-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCert, gotKey, err := Load(tt.certPath, tt.keyPath)
			if err == nil {
				t.Fatal("want error")
			}
			if gotCert != nil || gotKey != nil {
				t.Errorf("Load returned values alongside error: %v, %v", gotCert, gotKey)
			}
		})
	}
}
