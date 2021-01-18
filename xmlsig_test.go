package xmlsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

type Dummy struct {
	Value1 string
	Value2 int
}

func TestSigner_Sign(t *testing.T) {

	type s struct {
		input  interface{}
		assert func(got *Signature, err error)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		panic(err)
	}

	cert := newCertificate(key)

	cases := map[string]s{
		"simple": {
			input: &Dummy{
				Value1: "test-value",
				Value2: 12345678,
			},
			assert: func(got *Signature, err error) {
				assert.Nil(t, err)
				assert.NotNil(t, got)
			},
		},
	}

	for k, v := range cases {
		t.Run(k, func(t *testing.T) {

			unit, err := NewSigner(cert, key, SignerOptions{
				SignatureAlgorithm: SignatureAlgorithmDsigRSASHA256,
				DigestAlgorithm:    DigestAlgorithmDsigSHA256,
			})

			check(err)

			got, err := unit.CreateSignature(v.input)

			v.assert(got, err)

		})
	}

}

func newCertificate(privateKey *rsa.PrivateKey) *x509.Certificate {

	publicKey := privateKey.Public().(*rsa.PublicKey)

	now := time.Now()
	notBefore := now.AddDate(0, 0, -1)
	notAfter := now.AddDate(1, 0, 0)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	check(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)

	check(err)

	result, err := x509.ParseCertificate(derBytes)

	check(err)

	return result
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
