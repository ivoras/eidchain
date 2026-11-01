package chain

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// maxOCSPAge bounds how old a response without nextUpdate may be.
const maxOCSPAge = 24 * time.Hour

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
	var lastErr error
	for _, url := range cert.OCSPServer {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req))
		if err != nil {
			lastErr = err
			continue
		}
		httpReq.Header.Set("Content-Type", "application/ocsp-request")
		resp, err := client.Do(httpReq)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("OCSP responder %s: HTTP %d", url, resp.StatusCode)
			continue
		}
		if err := VerifyOCSP(body, cert, issuer, time.Now()); err != nil {
			lastErr = err
			continue
		}
		return body, nil
	}
	return nil, fmt.Errorf("OCSP check failed: %w", lastErr)
}

// VerifyOCSP checks a raw OCSP response offline: signed by the issuer (or its
// delegate), about this certificate, status good, and fresh at time now.
func VerifyOCSP(raw []byte, cert, issuer *x509.Certificate, now time.Time) error {
	r, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	if err != nil {
		return fmt.Errorf("OCSP response: %w", err)
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
	if !r.NextUpdate.IsZero() {
		if now.After(r.NextUpdate) {
			return errors.New("OCSP response has expired")
		}
	} else if now.Sub(r.ThisUpdate) > maxOCSPAge {
		return errors.New("OCSP response is too old")
	}
	return nil
}
