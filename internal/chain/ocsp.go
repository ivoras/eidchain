package chain

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"time"

	"golang.org/x/crypto/ocsp"
)

// maxOCSPAge bounds how old a response may be, whatever its nextUpdate says.
// Responses are also accepted from clients and peers, so a long nextUpdate must
// not let a stale "good" outlive a revocation.
const maxOCSPAge = 48 * time.Hour

// ErrOCSPUnavailable means no responder gave a usable answer: a temporary problem
// on someone else's side, as opposed to a certificate that was checked and failed.
var ErrOCSPUnavailable = errors.New("the OCSP responder could not be reached")

// FetchOCSP asks the certificate's OCSP responder (from its AIA extension)
// whether it is still good, and returns the verified raw response.
func FetchOCSP(ctx context.Context, client *http.Client, cert, issuer *x509.Certificate) ([]byte, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("certificate has no OCSP responder address")
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}
	var lastErr, rejected error
	for _, url := range cert.OCSPServer {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req))
		if err != nil {
			lastErr = err
			continue
		}
		httpReq.Header.Set("Content-Type", "application/ocsp-request")
		start := time.Now()
		resp, err := client.Do(httpReq)
		if err != nil {
			// Error path: the serial number is kept, to identify the certificate being debugged.
			log.Printf("ocsp: %s for serial %s: request failed after %s: %v", url, cert.SerialNumber.Text(16), time.Since(start).Round(time.Millisecond), err)
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			log.Printf("ocsp: %s for serial %s: HTTP %d, %d bytes, content-type %q, %s", url, cert.SerialNumber.Text(16),
				resp.StatusCode, len(body), resp.Header.Get("Content-Type"), time.Since(start).Round(time.Millisecond))
			lastErr = fmt.Errorf("OCSP responder %s: HTTP %d", url, resp.StatusCode)
			continue
		}
		if err := VerifyOCSP(body, cert, issuer, time.Now()); err != nil {
			log.Printf("ocsp: %s for serial %s: response rejected: %v", url, cert.SerialNumber.Text(16), err)
			rejected = fmt.Errorf("OCSP responder %s: %w", url, err)
			continue
		}
		log.Printf("ocsp: %s: good, %d bytes, %s", url, len(body), time.Since(start).Round(time.Millisecond)) // success: no serial (PII)
		return body, nil
	}
	if rejected != nil {
		return nil, fmt.Errorf("OCSP check failed: %w", rejected)
	}
	return nil, fmt.Errorf("%w: %v", ErrOCSPUnavailable, lastErr)
}

// VerifyOCSP checks a raw OCSP response offline: signed by the issuer (or its
// delegate), about this certificate, status good, and fresh at time now.
func VerifyOCSP(raw []byte, cert, issuer *x509.Certificate, now time.Time) error {
	r, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	if err != nil {
		return fmt.Errorf("OCSP response: %w", err)
	}
	if err := checkResponder(r, issuer, now); err != nil {
		return err
	}
	switch r.Status {
	case ocsp.Good:
	case ocsp.Revoked:
		return fmt.Errorf("certificate is revoked (since %s)", r.RevokedAt.Format(time.RFC3339))
	default:
		return errors.New("OCSP status is unknown")
	}
	if r.ThisUpdate.After(now.Add(5 * time.Minute)) {
		return errors.New("OCSP response is from the future")
	}
	if !r.NextUpdate.IsZero() && now.After(r.NextUpdate) {
		return errors.New("OCSP response has expired")
	}
	if now.Sub(r.ThisUpdate) > maxOCSPAge {
		return errors.New("OCSP response is too old")
	}
	return nil
}

// checkResponder enforces RFC 6960 4.2.2.2, which x/crypto/ocsp leaves to the
// caller: the library accepts any certificate the issuer signed as a responder,
// so without this a cardholder could sign "good" for their own revoked card.
func checkResponder(r *ocsp.Response, issuer *x509.Certificate, now time.Time) error {
	c := r.Certificate
	if c == nil || c.Equal(issuer) {
		return nil // signed by the issuer itself
	}
	if !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return errors.New("OCSP responder certificate is not authorised for OCSP signing")
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return errors.New("OCSP responder certificate is outside its validity period")
	}
	return nil
}
