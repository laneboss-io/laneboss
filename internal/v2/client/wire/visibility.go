package wire

import (
	"context"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// EventVisible is the common conservative delivery policy after scope auth.
func EventVisible(ctx context.Context, scope api.Scope, event api.Event) (bool, error) {
	if scope.Actor.Kind == "scheduler" {
		if err := api.CheckSchedulerScope(ctx, scope, time.Now()); err != nil {
			return false, err
		}
		return true, nil
	}
	if scope.Actor.Kind == "service" && scope.Connection == nil || scope.Actor.Kind == "watchdog" && scope.Source == "watchdog" && scope.Connection == nil && scope.Frame == nil && scope.Request.Method == "" {
		return true, nil
	}
	if scope.Actor.Kind == "human" {
		if scope.Connection == nil {
			return false, nil
		}
		if _, err := scope.Connection.ReadAuthority(ctx); err != nil {
			return false, err
		}
		return true, nil
	}
	if scope.Actor.Kind != "lane" {
		return false, nil
	}
	kind := string(event.Kind)
	if strings.HasPrefix(kind, "human.") || strings.HasPrefix(kind, "ticket.") || strings.HasPrefix(kind, "secret.") || strings.HasPrefix(kind, "channel.") {
		return false, nil
	}
	switch event.Kind {
	case "launch.planned", "loop.reserved", "capture.bound", "capture.refused":
		return false, nil
	case "mail.queued", "report.submitted":
		var mail api.Mail
		if err := Decode(event.Payload, &mail); err != nil {
			return false, err
		}
		return mail.Sender.LifeID == scope.Actor.LifeID || mail.RecipientLifeID == scope.Actor.LifeID, nil
	case "mail.delivered", "mail.returned":
		var receipt api.MailReceipt
		if err := Decode(event.Payload, &receipt); err != nil {
			return false, err
		}
		return receipt.Target.LifeID == scope.Actor.LifeID, nil
	}
	return true, nil
}
