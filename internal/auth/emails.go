package auth

import (
	"encoding/base64"
	"fmt"
	"net/url"
)

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// link builds publicURL + path + ?token=… . Tokens go to the dashboard page,
// which POSTs them to the API, so a link prefetcher (mail scanners) can't
// consume them with a GET.
func link(publicURL *url.URL, path, token string) string {
	u := *publicURL
	u.Path = u.Path + path
	u.RawQuery = url.Values{"token": {token}}.Encode()
	return u.String()
}

// VerificationEmail is sent after registration.
func VerificationEmail(publicURL *url.URL, to, token string) Message {
	return Message{To: to, Subject: "Verify your WireMesh email address", Text: fmt.Sprintf(
		"Welcome to WireMesh.\n\nConfirm your email address by opening this link within 24 hours:\n\n%s\n\n"+
			"If you didn't create an account, ignore this email.\n", link(publicURL, "/verify-email", token))}
}

// PasswordResetEmail is sent on "forgot password".
func PasswordResetEmail(publicURL *url.URL, to, token string) Message {
	return Message{To: to, Subject: "Reset your WireMesh password", Text: fmt.Sprintf(
		"Someone asked to reset the password for this WireMesh account.\n\nOpen this link within 1 hour to choose a new password:\n\n%s\n\n"+
			"If it wasn't you, ignore this email: your password hasn't changed.\n", link(publicURL, "/reset-password", token))}
}

// AccountExistsEmail is sent instead of an error when someone registers with
// an address that already has an account (prevents account enumeration).
func AccountExistsEmail(publicURL *url.URL, to string) Message {
	u := *publicURL
	u.Path += "/forgot-password"
	return Message{To: to, Subject: "WireMesh sign-up attempt", Text: fmt.Sprintf(
		"Someone tried to create a WireMesh account with this email address, but you already have one.\n\n"+
			"If that was you, sign in, or reset your password here:\n\n%s\n", u.String())}
}
