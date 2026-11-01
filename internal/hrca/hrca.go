// Package hrca embeds the Croatian eID CA certificates (AKDCA Root and HRIDCA)
// published at https://eid.hr/en/certificates/certificates-akdca-root-and-hridca.
// They are the default trust anchors for `eidchain genesis`: a running chain
// uses the ones fixed in its genesis block.
package hrca

import _ "embed"

// PEM holds AKDCA Root and HRIDCA.
//
//go:embed hr-eid-ca.pem
var PEM string

// Builtin returns an embedded CA bundle by name ("hr").
func Builtin(name string) (string, bool) {
	if name == "hr" {
		return PEM, true
	}
	return "", false
}
