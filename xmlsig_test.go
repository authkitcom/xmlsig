package xmlsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
	"time"
)

type Dummy struct {
	Value1 string
	Value2 int
}

type signatureAlgorithm struct {
	algorithm string
	digest    string
}

var signatureAlgorithms = []signatureAlgorithm{
	{
		algorithm: SignatureAlgorithmDsigRSASHA1,
		digest:    DigestAlgorithmDsigRSASHA1,
	},
	{
		algorithm: SignatureAlgorithmDsigRSASHA256,
		digest:    DigestAlgorithmDsigSHA256,
	},
}

func TestSigner_CreateSignature_VerifySignature(t *testing.T) {

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
		},
	}

	for _, a := range signatureAlgorithms {
		for k, v := range cases {
			t.Run(fmt.Sprintf("%s-%s-%s", a.algorithm, a.digest, k), func(t *testing.T) {

				unit, err := NewSigner(cert, key, SignerOptions{
					SignatureAlgorithm: a.algorithm,
					DigestAlgorithm:    a.digest,
				})

				check(err)

				got, err := unit.CreateSignature(v.input)

				assert.Nil(t, err)
				assert.NotNil(t, got)

				unit2, err := NewVerifier(cert, VerifierOptions{
					SignatureAlgorithm: a.algorithm,
					DigestAlgorithm:    a.digest,
				})

				check(err)

				got2, err := unit2.VerifySignature(v.input, got)

				assert.True(t, got2)
				assert.Nil(t, err)

				unit3, err := NewVerifier(cert, VerifierOptions{
					SignatureAlgorithm: a.algorithm,
					DigestAlgorithm:    a.digest,
					X509Data:           got.KeyInfo.X509Data.X509Certificate,
				})

				check(err)

				assert.Nil(t, err)

				got3, err := unit3.VerifySignature(v.input, got)

				assert.True(t, got3)
				assert.Nil(t, err)

				unit4, err := NewVerifier(cert, VerifierOptions{
					SignatureAlgorithm: a.algorithm,
					DigestAlgorithm:    a.digest,
					X509Data:           "invalid",
				})

				assert.Nil(t, unit4)
				assert.EqualError(t, err, "certificate mismatch")

			})
		}
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
