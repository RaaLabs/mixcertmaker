package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"log"
)

func main() {
	years := flag.Int("years", 100, "number of years that the certificate will be valid")
	flag.Parse()

	cert := "Swupd_Root.pem"

	privkey, err := CreateKeyPair()
	if err != nil {
		fmt.Printf("Error generating OpenSSL keypair %v\n", err)
	}

	template := CreateCertTemplate(*years)

	err = GenerateCertificate(cert, template, template, &privkey.PublicKey, privkey)
	if err != nil {
		fmt.Printf("error: GenerateCertificate: %v", err)
	}
}

// CreateKeyPair constructs an RSA keypair in memory
func CreateKeyPair() (*rsa.PrivateKey, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("Failed to generate random key %v\n", err)
	}
	return rootKey, nil
}

// CreateCertTemplate will construct the template for needed openssl metadata
// instead of using an attributes.cnf file
func CreateCertTemplate(years int) *x509.Certificate {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialnumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("Failed to generate serial number %v\n", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialnumber,
		Subject:               pkix.Name{Organization: []string{"Mixer"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(years, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false, // This could be true since we are self signed, but set false for correctness
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	return &template
}

// GenerateCertificate will create the private signing key and public
// certificate for clients to use and writes them to disk
func GenerateCertificate(cert string, template, parent *x509.Certificate, pubkey interface{}, privkey interface{}) error {
	if _, err := os.Stat(cert); os.IsNotExist(err) {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, pubkey, privkey)
		if err != nil {
			return err
		}

		// Write the public certficiate out for clients to use
		certOut, err := os.Create(cert)
		if err != nil {
			return err
		}
		err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err != nil {
			return err
		}
		err = certOut.Close()
		if err != nil {
			return err
		}

		// Write the private signing key out
		keyOut, err := os.OpenFile(filepath.Dir(cert)+"/private.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}

		defer func() {
			_ = keyOut.Close()
		}()

		// Need type assertion for Marshal to work
		priv := privkey.(*rsa.PrivateKey)
		err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		if err != nil {
			return err
		}
	}
	return nil
}
