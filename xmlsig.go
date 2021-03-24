// Package xmlsig supports add XML Digital Signatures to Go structs marshalled to XML.
package xmlsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	// import supported crypto hash function
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

const (
	SignatureAlgorithmDsigRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureAlgorithmDsigRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

const (
	DigestAlgorithmDsigRSASHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	DigestAlgorithmDsigSHA256  = "http://www.w3.org/2001/04/xmlenc#sha256"
)

// Signer is used to create a Signature for the provided object.
type Signer interface {
	Sign([]byte) (string, error)
	CreateSignature(interface{}) (*Signature, error)
	Algorithm() string
}

type Verifier interface {
	Verify([]byte, *Signature) (bool, error)
	VerifySignature(interface{}, *Signature) (bool, error)
	Algorithm() string
}

type signer struct {
	cert      *x509.Certificate
	key       *rsa.PrivateKey
	sigAlg    *algorithm
	digestAlg *algorithm
}

type verifier struct {
	cert      *x509.Certificate
	sigAlg    *algorithm
	digestAlg *algorithm
}

type algorithm struct {
	name string
	hash crypto.Hash
}

type SignerOptions struct {
	SignatureAlgorithm string
	DigestAlgorithm    string
}

type VerifierOptions struct {
	SignatureAlgorithm string
	DigestAlgorithm    string
	// If specified, is compared against the certificate data for equality
	X509Data string
}

var Canonicalize = canonicalize

func pickSignatureAlgorithm(certType x509.PublicKeyAlgorithm, alg string) (*algorithm, error) {
	var hash crypto.Hash
	switch certType {
	case x509.RSA:
		switch alg {
		case "":
			alg = SignatureAlgorithmDsigRSASHA1
			hash = crypto.SHA1
		case SignatureAlgorithmDsigRSASHA1:
			hash = crypto.SHA1
		case SignatureAlgorithmDsigRSASHA256:
			hash = crypto.SHA256
		default:
			return nil, errors.New("xmlsig does not currently the specfied algorithm for RSA certificates")
		}
	default:
		return nil, errors.New("xmlsig needs some work to support your certificate")
	}
	return &algorithm{alg, hash}, nil
}

func pickDigestAlgorithm(alg string) (*algorithm, error) {
	switch alg {
	case "":
		fallthrough
	case DigestAlgorithmDsigRSASHA1:
		return &algorithm{"http://www.w3.org/2000/09/xmldsig#sha1", crypto.SHA1}, nil
	case DigestAlgorithmDsigSHA256:
		return &algorithm{"http://www.w3.org/2001/04/xmlenc#sha256", crypto.SHA256}, nil
	}
	return nil, errors.New("xmlsig does not support the specified digest algorithm")
}

// NewSigner creates a new Signer with the certificate and options
func NewSigner(cert *x509.Certificate, key *rsa.PrivateKey, options ...SignerOptions) (Signer, error) {
	opts := SignerOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	sigAlg, err := pickSignatureAlgorithm(cert.PublicKeyAlgorithm, opts.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	digestAlg, err := pickDigestAlgorithm(opts.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	return &signer{cert, key, sigAlg, digestAlg}, nil
}

func (s *signer) Algorithm() string {
	return s.sigAlg.name
}

func (s *signer) CreateSignature(data interface{}) (*Signature, error) {
	signature := newSignature()
	signature.SignedInfo.SignatureMethod.Algorithm = s.sigAlg.name
	signature.SignedInfo.Reference.DigestMethod.Algorithm = s.digestAlg.name
	// canonicalize the Item
	canonData, id, err := Canonicalize(data, signature.SignedInfo.SignatureMethod.Algorithm, "", false)
	if err != nil {
		return nil, err
	}
	if id != "" {
		signature.SignedInfo.Reference.URI = "#" + id
	}
	// calculate the digest
	digest := digest(s.digestAlg, canonData)
	signature.SignedInfo.Reference.DigestValue = digest
	// Canonicalize the SignedInfo
	canonData, _, err = Canonicalize(signature.SignedInfo, signature.SignedInfo.SignatureMethod.Algorithm, "",false)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(canonData)
	if err != nil {
		return nil, err
	}
	signature.SignatureValue = sig
	x509Data := &X509Data{X509Certificate: base64.StdEncoding.EncodeToString(s.cert.Raw)}
	signature.KeyInfo.X509Data = x509Data
	return signature, nil
}

func (s *signer) Sign(data []byte) (string, error) {
	h := s.sigAlg.hash.New()
	h.Write(data)
	sum := h.Sum(nil)
	sig, err := s.key.Sign(rand.Reader, sum, s.sigAlg.hash)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// NewVerifier creates a new Signer with the certificate and options
func NewVerifier(cert *x509.Certificate, options ...VerifierOptions) (Verifier, error) {
	opts := VerifierOptions{}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.X509Data != "" {
		if base64.StdEncoding.EncodeToString(cert.Raw) != opts.X509Data {
			return nil, errors.New("certificate mismatch")
		}
	}
	sigAlg, err := pickSignatureAlgorithm(cert.PublicKeyAlgorithm, opts.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	digestAlg, err := pickDigestAlgorithm(opts.DigestAlgorithm)
	if err != nil {
		return nil, err
	}
	return &verifier{cert, sigAlg, digestAlg}, nil
}

func (s *verifier) Algorithm() string {
	return s.sigAlg.name
}

func (s *verifier) VerifySignature(data interface{}, signature *Signature) (bool, error) {
	// Canonicalize the Item
	canonData, _, err := Canonicalize(data, s.sigAlg.name, "",false)
	if err != nil {
		return false, err
	}
	return s.Verify(canonData, signature)
}

// TODO - Check mismatch of digest and signature methods
func (s *verifier) Verify(data []byte, signature *Signature) (bool, error) {
	h := s.sigAlg.hash.New()
	h.Write(data)
	digestSum := h.Sum(nil)
	if base64.StdEncoding.EncodeToString(digestSum) != signature.SignedInfo.Reference.DigestValue {
		return false, nil
	}
	canonData, _, err := Canonicalize(signature.SignedInfo, s.sigAlg.name, "",false)
	if err != nil {
		return false, err
	}
	h = s.sigAlg.hash.New()
	h.Write(canonData)
	sigSum := h.Sum(nil)
	sig, err := base64.StdEncoding.DecodeString(signature.SignatureValue)
	if err != nil {
		return false, err
	}
	return rsa.VerifyPKCS1v15(s.cert.PublicKey.(*rsa.PublicKey), s.digestAlg.hash, sigSum, sig) == nil, nil
}

func newSignature() *Signature {
	signature := &Signature{}
	signature.SignedInfo.CanonicalizationMethod.Algorithm =
		"http://www.w3.org/2001/10/xml-exc-c14n#"
	transforms := &signature.SignedInfo.Reference.Transforms.Transform
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2001/10/xml-exc-c14n#"})
	return signature
}

func digest(digestAlg *algorithm, data []byte) string {
	h := digestAlg.hash.New()
	h.Write(data)
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}
