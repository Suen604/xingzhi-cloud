package extended

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/abusereport"
	"github.com/cloudreve/Cloudreve/v4/ent/auditlog"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/hashid"
	"github.com/gin-gonic/gin"
)

// Audit records metadata only. Passwords, request/response bodies, tokens and
// query strings are deliberately excluded from persistent audit records.
func Audit() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if c.FullPath() == "" || c.Request.Method == http.MethodOptions {
			return
		}
		config, err := readConfig(c)
		if err != nil || !config.Audit {
			return
		}
		actor := 0
		if u := inventory.UserFromContext(c); u != nil && !inventory.IsAnonymousUser(u) {
			actor = u.ID
		}
		dep := dependency.FromContext(c)
		_, err = dep.DBClient().AuditLog.Create().SetActorID(actor).SetAction(c.Request.Method + " " + c.FullPath()).
			SetResource(c.Request.URL.Path).SetIP(c.ClientIP()).SetStatus(c.Writer.Status()).Save(c)
		if err != nil {
			dep.Logger().Warning("Failed to persist audit metadata: %s", err)
		}
	}
}

func ListAudit(c *gin.Context) {
	query := dependency.FromContext(c).DBClient().AuditLog.Query()
	if actor, err := strconv.Atoi(c.Query("actor")); err == nil {
		query.Where(auditlog.ActorID(actor))
	}
	if action := c.Query("action"); action != "" {
		query.Where(auditlog.ActionContains(strings.TrimSpace(action)))
	}
	page, size := pagination(c)
	total, err := query.Clone().Count(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	items, err := query.Order(ent.Desc(auditlog.FieldID)).Offset((page - 1) * size).Limit(size).All(c)
	response(c, map[string]any{"items": items, "total": total}, err)
}

func ReportAbuse(c *gin.Context) {
	var input struct {
		Share  string `json:"share" binding:"required"`
		Reason string `json:"reason" binding:"required,min=5,max=2000"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	dep := dependency.FromContext(c)
	id, err := dep.HashIDEncoder().Decode(input.Share, hashid.ShareID)
	if err != nil {
		response(c, nil, errors.New("invalid share"))
		return
	}
	if _, err := dep.DBClient().Share.Get(c, id); err != nil {
		response(c, nil, errors.New("share not found"))
		return
	}
	report, err := dep.DBClient().AbuseReport.Create().SetShareID(id).SetReporterID(inventory.UserFromContext(c).ID).SetReason(input.Reason).Save(c)
	response(c, report, err)
}

func ListReports(c *gin.Context) {
	query := dependency.FromContext(c).DBClient().AbuseReport.Query()
	page, size := pagination(c)
	total, err := query.Clone().Count(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	items, err := query.Order(ent.Desc(abusereport.FieldID)).Offset((page - 1) * size).Limit(size).All(c)
	response(c, map[string]any{"items": items, "total": total}, err)
}

func ResolveReport(c *gin.Context) {
	var input struct {
		Status       string `json:"status" binding:"required,oneof=resolved dismissed"`
		Resolution   string `json:"resolution" binding:"max=2000"`
		DisableShare bool   `json:"disable_share"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		response(c, nil, err)
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		response(c, nil, err)
		return
	}
	tx, err := dependency.FromContext(c).DBClient().Tx(c)
	if err != nil {
		response(c, nil, err)
		return
	}
	defer tx.Rollback()
	report, err := tx.AbuseReport.Get(c, id)
	if err != nil {
		response(c, nil, err)
		return
	}
	if input.DisableShare {
		if err := tx.Share.DeleteOneID(report.ShareID).Exec(c); err != nil && !ent.IsNotFound(err) {
			response(c, nil, err)
			return
		}
	}
	_, err = tx.AbuseReport.UpdateOne(report).SetStatus(abusereport.Status(input.Status)).SetResolution(input.Resolution).Save(c)
	if err == nil {
		err = tx.Commit()
	}
	response(c, map[string]bool{"saved": err == nil}, err)
}
