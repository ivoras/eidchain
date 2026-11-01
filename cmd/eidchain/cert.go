package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"eidchain/internal/chain"
)

// cmdCert explains whether an eID certificate would be accepted by the chain in
// the data directory, and if not, which CA it needs. Get the certificate from
// the /signer page (the ".signer.pem" download) or from your card middleware.
func cmdCert(args []string) error {
	fs := newFlagSet("cert")
	data := fs.String("data", defaultData(), "data directory whose genesis supplies the trusted CAs")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: eidchain cert [flags] CERT-FILE (PEM or DER)")
	}
	raw, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	if blk, _ := pem.Decode(raw); blk != nil {
		raw = blk.Bytes
	}
	c, err := x509.ParseCertificate(raw)
	if err != nil {
		return fmt.Errorf("not a certificate: %w", err)
	}
	fp := sha256.Sum256(c.Raw)
	fmt.Printf("subject:      %s\nissuer:       %s\nserial:       %s\nvalid:        %s to %s\nsha256:       %x\n",
		c.Subject, c.Issuer, c.SerialNumber.Text(16), c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"), fp)
	fmt.Printf("key usage:    %s\nauthority key id: %x\nOCSP:         %v\nissuer cert:  %v\nCRL:          %v\n",
		chain.KeyUsageNames(c), c.AuthorityKeyId, c.OCSPServer, c.IssuingCertificateURL, c.CRLDistributionPoints)

	g, err := chain.LoadGenesis(chain.GenesisPath(*data))
	if err != nil {
		fmt.Printf("\n(no chain in %s, so no trust check: %v)\n", *data, err)
		return nil
	}
	p, err := chain.NewParams(g)
	if err != nil {
		return err
	}
	fmt.Printf("\nchain %s trusts:\n", p.GenesisHash.Short())
	for _, a := range p.Trust.Certificates() {
		match := ""
		if len(c.AuthorityKeyId) > 0 && string(a.SubjectKeyId) == string(c.AuthorityKeyId) {
			match = "   <- this certificate's issuer"
		}
		fmt.Printf("  %s (key id %x)%s\n", chain.CertName(a), a.SubjectKeyId, match)
	}
	switch err := p.Trust.Verify(c, nil, time.Now()); {
	case err != nil:
		fmt.Printf("\nNOT trusted: %v\n", err)
		if len(c.IssuingCertificateURL) > 0 {
			fmt.Printf("The issuing CA certificate is probably at %v.\nDownload it (and its parents), then create a chain that trusts it:\n  eidchain genesis --trust-ca builtin:hr --trust-ca THAT-CA.pem …\n", c.IssuingCertificateURL)
		}
	case c.KeyUsage&x509.KeyUsageContentCommitment == 0 && p.Rules.RequireNonRepudiation:
		fmt.Println("\nTrusted, but it lacks the non-repudiation key usage: the chain would refuse it as a payload signer (it may be the authentication certificate).")
	default:
		fmt.Println("\nTrusted: the chain accepts this certificate for payload signatures.")
	}
	return nil
}
