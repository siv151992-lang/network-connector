package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/siv151992-lang/network-connector/internal/api/httpx"
	"github.com/siv151992-lang/network-connector/internal/auth"
	"github.com/siv151992-lang/network-connector/internal/store"
)

// System-administration endpoints (system_role = admin).
func (s *Server) adminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/admin/users", s.handle(s.sysAdmin(s.handleAdminListUsers)))
	mux.HandleFunc("POST /api/v1/admin/users", s.handle(s.sysAdmin(s.handleAdminCreateUser)))
	mux.HandleFunc("PATCH /api/v1/admin/users/{uid}", s.handle(s.sysAdmin(s.handleAdminUpdateUser)))
}

func (s *Server) handleAdminListUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	users, total, err := s.store.ListUsers(r.Context(), limit, offset)
	if err != nil {
		return err
	}
	if users == nil {
		users = []*store.User{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"users": users, "total": total})
	return nil
}

type adminCreateUserReq struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	SystemRole  string `json:"system_role"`
}

// handleAdminCreateUser creates an already-verified account. This is how
// users are added when self-registration is disabled (the default).
func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	var req adminCreateUserReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	req.Email = store.NormalizeEmail(req.Email)
	if req.SystemRole == "" {
		req.SystemRole = store.SystemRoleUser
	}
	f := fieldErrors{}
	if !validEmail(req.Email) {
		f.add("email", "must be a valid email address")
	}
	if msg := auth.ValidatePassword(req.Password, req.Email); msg != "" {
		f.add("password", "%s", msg)
	}
	if req.SystemRole != store.SystemRoleUser && req.SystemRole != store.SystemRoleAdmin {
		f.add("system_role", "must be user or admin")
	}
	validateDisplayName(f, req.DisplayName)
	if err := f.err(); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(r.Context(), req.Password)
	if err != nil {
		return err
	}
	u, err := s.store.CreateUser(r.Context(), store.NewUser{Email: req.Email, PasswordHash: hash,
		DisplayName: req.DisplayName, SystemRole: req.SystemRole, Verified: true})
	if errors.Is(err, store.ErrConflict) {
		return httpx.Conflict("an account with this email already exists")
	}
	if err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "admin.user_create", TargetType: "user",
		TargetID: u.ID.String(), Metadata: map[string]any{"system_role": u.SystemRole}})
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"user": u})
	return nil
}

type adminUpdateUserReq struct {
	Disabled   *bool   `json:"disabled"`
	SystemRole *string `json:"system_role"`
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	uid, err := pathUUID(r, "uid")
	if err != nil {
		return err
	}
	var req adminUpdateUserReq
	if err := httpx.DecodeJSON(r, &req); err != nil {
		return err
	}
	if uid == p.User.ID {
		return httpx.Forbidden("you cannot change your own account status or role")
	}
	if req.SystemRole != nil && *req.SystemRole != store.SystemRoleUser && *req.SystemRole != store.SystemRoleAdmin {
		return httpx.Validation(map[string]string{"system_role": "must be user or admin"})
	}
	err = s.store.WithTx(r.Context(), func(tx *store.Store) error {
		if req.Disabled != nil {
			if err := tx.SetUserDisabled(r.Context(), uid, *req.Disabled); err != nil {
				return err
			}
			if *req.Disabled {
				if _, err := tx.RevokeUserSessions(r.Context(), uid, uuid.Nil); err != nil {
					return err
				}
			}
		}
		if req.SystemRole != nil {
			return tx.SetSystemRole(r.Context(), uid, *req.SystemRole)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.audit(r, store.NewAuditEntry{ActorUserID: &p.User.ID, Action: "admin.user_update", TargetType: "user",
		TargetID: uid.String(), Metadata: map[string]any{"disabled": req.Disabled, "system_role": req.SystemRole}})
	u, err := s.store.GetUser(r.Context(), uid)
	if err != nil {
		return err
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user": u})
	return nil
}
