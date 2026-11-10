package api

import "testing"

// Standalone first run: with no users, the first sign-up becomes the system
// admin (verified, no email needed); after that, registration is closed again.
func TestE2EFirstUserSetup(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string]string{
		"WIREMESH_ALLOW_REGISTRATION": "false", "WIREMESH_FIRST_USER_SETUP": "true",
		"WIREMESH_REQUIRE_EMAIL_VERIFICATION": "true",
	})
	c := e.client()
	if r := c.must(200, "GET", "/api/v1/auth/setup", nil).json(t); get(r, "setup_required") != true {
		t.Fatalf("setup should be required: %v", r)
	}
	c.must(201, "POST", "/api/v1/auth/register", map[string]string{"email": "first@example.com", "password": pw})
	c.errCode(403, "registration_disabled", "POST", "/api/v1/auth/register", map[string]string{"email": "second@example.com", "password": pw})
	if r := c.must(200, "GET", "/api/v1/auth/setup", nil).json(t); get(r, "setup_required") != false {
		t.Fatalf("setup should be done: %v", r)
	}
	me := e.loggedIn("first@example.com", pw).must(200, "GET", "/api/v1/auth/me", nil).json(t)
	if get(me, "user.system_role") != "admin" {
		t.Fatalf("first user is not admin: %v", me)
	}
	if _, ok := e.mail.Last("first@example.com"); ok {
		t.Fatal("no verification email expected for the first user")
	}

	// Without the flag nothing changes: setup is never offered.
	e2 := newEnv(t, map[string]string{"WIREMESH_ALLOW_REGISTRATION": "false"})
	if r := e2.client().must(200, "GET", "/api/v1/auth/setup", nil).json(t); get(r, "setup_required") != false {
		t.Fatalf("setup offered without the flag: %v", r)
	}
	e2.client().errCode(403, "registration_disabled", "POST", "/api/v1/auth/register", map[string]string{"email": "x@example.com", "password": pw})
}
