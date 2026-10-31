package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func listUsers(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		users, err := deps.Store.Users().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, users)
	}
}

func createUser(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
			Role     string `json:"role"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Role == "" {
			req.Role = "viewer"
		}
		hash, err := hashPassword(req.Password)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, "hash failed")
			return
		}
		id, err := deps.Store.Users().Create(c, &store.User{
			Username: req.Username, Password: hash, Role: req.Role, Enabled: true,
		})
		if err != nil {
			dbError(c, "", err)
			return
		}
		auditDirect(c, deps, "user", strconv.Itoa(id), "create", makeDiff(nil, userAuditView(&store.User{
			Username: req.Username, Role: req.Role, Enabled: true,
		})))
		created(c, gin.H{"id": id})
	}
}

func updateUser(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Enabled  *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		user, err := deps.Store.Users().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "user not found")
			return
		}
		old := userAuditView(user)
		passwordChanged := false
		if req.Username != "" {
			user.Username = req.Username
		}
		if pw := strings.TrimSpace(req.Password); pw != "" {
			hash, err := hashPassword(pw)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, "hash failed")
				return
			}
			user.Password = hash
			passwordChanged = true
		}
		if req.Role != "" {
			user.Role = req.Role
		}
		if req.Enabled != nil {
			user.Enabled = *req.Enabled
		}
		if err := deps.Store.Users().Update(c, user); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				errResponse(c, http.StatusConflict, store.ErrLastAdmin.Error())
				return
			}
			dbError(c, "", err)
			return
		}
		newView := userAuditView(user)
		newView["password_changed"] = passwordChanged
		auditDirect(c, deps, "user", strconv.Itoa(id), "update", makeDiff(old, newView))
		ok(c, gin.H{"ok": true})
	}
}

func deleteUser(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var old any = gin.H{"id": id}
		if user, err := deps.Store.Users().Get(c, id); err == nil && user != nil {
			old = userAuditView(user)
		}
		if err := deps.Store.Users().Delete(c, id); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				errResponse(c, http.StatusConflict, store.ErrLastAdmin.Error())
				return
			}
			dbError(c, "", err)
			return
		}
		auditDirect(c, deps, "user", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func userAuditView(user *store.User) gin.H {
	return gin.H{"username": user.Username, "role": user.Role, "enabled": user.Enabled}
}

// auditDirect records a successful user or node request without publishing configuration.
func auditDirect(c *gin.Context, deps Dependencies, entityType, entityID, action string, diff json.RawMessage) {
	var userID *int
	if uid, exists := c.Get("user_id"); exists {
		id := uid.(int)
		userID = &id
		if entityType == "user" && action == "delete" && entityID == strconv.Itoa(id) {
			userID = nil
		}
	}
	if err := deps.Store.AuditLog().Create(c, &store.AuditLog{
		UserID: userID, EntityType: entityType, EntityID: entityID,
		Action: action, Diff: diff, DeliveryVersion: nil,
	}); err != nil {
		log.Printf("ERROR api: audit %s %s %s: %v", entityType, action, entityID, err)
	}
}
