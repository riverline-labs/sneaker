package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// teamNamePattern validates team names: lowercase alphanumeric + hyphens, 2-32 chars.
// Must start and end with alphanumeric. Middle allows hyphens.
var teamNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$`)

// handleCreateTeam creates a new team and adds the authenticated user as owner.
// POST /api/teams
func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	name := strings.ToLower(strings.TrimSpace(req.Name))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "team name is required"})
		return
	}

	if !teamNamePattern.MatchString(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "team name must be 2-32 lowercase alphanumeric characters or hyphens, starting and ending with alphanumeric"})
		return
	}

	team, err := s.store.CreateTeam(r.Context(), name, user.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "team name already taken"})
			return
		}
		slog.Error("failed to create team", "error", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("team created", "team", name, "owner_id", user.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"name": team.Name, "id": team.ID})
}

// handleListTeams returns teams the authenticated user belongs to.
// GET /api/teams
func (s *Server) handleListTeams(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	teams, err := s.store.ListUserTeams(r.Context(), user.ID)
	if err != nil {
		slog.Error("failed to list teams", "error", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Build response array; never return null -- always an empty array.
	items := make([]map[string]any, 0, len(teams))
	for _, t := range teams {
		role := "member"
		if t.CreatorID == user.ID {
			role = "owner"
		}
		items = append(items, map[string]any{
			"name": t.Name,
			"role": role,
		})
	}

	writeJSON(w, http.StatusOK, items)
}

// handleListTeamMembers returns members of a team with their emails, roles, and public keys.
// Only accessible to team members. Non-members get 403.
// GET /api/teams/{name}/members
func (s *Server) handleListTeamMembers(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	name := r.PathValue("name")

	team, err := s.store.GetTeamByName(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "team not found"})
		return
	}

	isMember, err := s.store.IsTeamMember(r.Context(), team.ID, user.ID)
	if err != nil {
		slog.Error("failed to check team membership", "error", err, "team_id", team.ID, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if !isMember {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "not a team member"})
		return
	}

	members, err := s.store.ListTeamMembers(r.Context(), team.ID)
	if err != nil {
		slog.Error("failed to list team members", "error", err, "team_id", team.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Build response array; never return null -- always an empty array.
	items := make([]map[string]any, 0, len(members))
	for _, m := range members {
		item := map[string]any{
			"email": m.Email,
			"role":  m.Role,
		}
		if m.PublicKey != "" {
			item["public_key"] = m.PublicKey
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, items)
}

// handleCreateInvite generates an invite token for a team. Only the team owner can create invites.
// POST /api/teams/{name}/invites
func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	name := r.PathValue("name")

	team, err := s.store.GetTeamByName(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "team not found"})
		return
	}

	if team.CreatorID != user.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "only the team owner can create invites"})
		return
	}

	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)
	token, err := s.store.CreateInvite(r.Context(), team.ID, user.ID, expiresAt)
	if err != nil {
		slog.Error("failed to create invite", "error", err, "team_id", team.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	slog.Info("invite created", "team", name, "created_by", user.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      token,
		"team":       team.Name,
		"expires_at": expiresAt.Format("2006-01-02T15:04:05Z"),
	})
}

// handleJoinTeam redeems an invite token and adds the authenticated user to the team.
// POST /api/teams/join
func (s *Server) handleJoinTeam(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	teamName, err := s.store.RedeemInvite(r.Context(), req.Token, user.ID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite token invalid or expired"})
		return
	}

	slog.Info("user joined team", "team", teamName, "user_id", user.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"team":    teamName,
		"message": "joined team",
	})
}
