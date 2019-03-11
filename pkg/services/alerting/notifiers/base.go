package notifiers

import (
	"context"
	"time"

	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/alerting"
)

const (
	triggMetrString = "Triggered metrics:\n\n"
)

type NotifierBase struct {
	Name                   string
	Type                   string
	Uid                    string
	IsDefault              bool
	UploadImage            bool

	SendReminder           bool
	Frequency              time.Duration

	DisableResolveMessage  bool
	DisableAlertingMessage bool
	DisableNoDataMessage   bool
	DisableUnknownMessage  bool
	DisablePendingMessage  bool

	log log.Logger
}

func NewNotifierBase(model *models.AlertNotification) NotifierBase {
	uploadImage := true
	value, exist := model.Settings.CheckGet("uploadImage")
	if exist {
		uploadImage = value.MustBool()
	}

	return NotifierBase{
		Uid:                    model.Uid,
		Name:                   model.Name,
		IsDefault:              model.IsDefault,
		Type:                   model.Type,
		UploadImage:            uploadImage,
		SendReminder:           model.SendReminder,
		DisableResolveMessage:  model.DisableResolveMessage,
		DisableAlertingMessage: model.DisableAlertingMessage,
		DisableNoDataMessage:   model.DisableNoDataMessage,
		DisableUnknownMessage:  model.DisableUnknownMessage,
		DisablePendingMessage:  model.DisablePendingMessage,
		Frequency:              model.Frequency,
		log:                    log.New("alerting.notifier." + model.Name),
	}
}

// ShouldNotify checks this evaluation should send an alert notification
func (n *NotifierBase) ShouldNotify(ctx context.Context, context *alerting.EvalContext, notifierState *models.AlertNotificationState) bool {
	// Only notify on state change.
	if context.PrevAlertState == context.Rule.State && !n.SendReminder {
		return false
	}

	if context.PrevAlertState == context.Rule.State && n.SendReminder {
		// Do not notify if interval has not elapsed
		lastNotify := time.Unix(notifierState.UpdatedAt, 0)
		if notifierState.UpdatedAt != 0 && lastNotify.Add(n.Frequency).After(time.Now()) {
			return false
		}

		// Do not notify if alert state is OK or pending even on repeated notify
		if context.Rule.State == models.AlertStateOK || context.Rule.State == models.AlertStatePending {
			return false
		}
	}

	// Do not notify when we become OK for the first time.
	if context.PrevAlertState == models.AlertStateUnknown && context.Rule.State == models.AlertStateOK {
		return false
	}

	// Do not notify when we become OK for the first time.
	if context.PrevAlertState == models.AlertStateUnknown && context.Rule.State == models.AlertStatePending {
		return false
	}

	// Do not notify when we become OK from Pending
	if context.PrevAlertState == models.AlertStatePending && context.Rule.State == models.AlertStateOK {
		return false
	}

	// Do not notify when we OK -> Pending
	if context.PrevAlertState == models.AlertStateOK && context.Rule.State == models.AlertStatePending {
		return false
	}

	// Do not notify if state is Pending and it have been updated last minute
	if notifierState.State == models.AlertNotificationStatePending {
		lastUpdated := time.Unix(notifierState.UpdatedAt, 0)
		if lastUpdated.Add(1 * time.Minute).After(time.Now()) {
			return false
		}
	}

	// Do not notify when state is Alerting if DisableAlertingMessage is set to true
	if context.Rule.State == models.AlertStateAlerting && n.DisableAlertingMessage {
		return false
	}

	// Do not notify when state is NoData if DisableNoDataMessage is set to true
	if context.Rule.State == models.AlertStateNoData && n.DisableNoDataMessage {
		return false
	}

	// Do not notify when state is Unknown if DisableUnknownMessage is set to true
	if context.Rule.State == models.AlertStateUnknown && n.DisableUnknownMessage {
		return false
	}

	// Do not notify when state is Pending if DisablePendingMessage is set to true
	if context.Rule.State == models.AlertStatePending && n.DisablePendingMessage {
		return false
	}

	// Do not notify when state is OK if DisableResolveMessage is set to true
	if context.Rule.State == models.AlertStateOK && n.DisableResolveMessage {
		return false
	}

	return true
}

func (n *NotifierBase) GetType() string {
	return n.Type
}

func (n *NotifierBase) NeedsImage() bool {
	return n.UploadImage
}

func (n *NotifierBase) GetNotifierUid() string {
	return n.Uid
}

func (n *NotifierBase) GetIsDefault() bool {
	return n.IsDefault
}

func (n *NotifierBase) GetSendReminder() bool {
	return n.SendReminder
}

func (n *NotifierBase) GetDisableResolveMessage() bool {
	return n.DisableResolveMessage
}

func (n *NotifierBase) GetDisableAlertingMessage() bool {
	return n.DisableAlertingMessage
}

func (n *NotifierBase) GetDisableNoDataMessage() bool {
	return n.DisableNoDataMessage
}

func (n *NotifierBase) GetDisableUnknownMessage() bool {
	return n.DisableUnknownMessage
}

func (n *NotifierBase) GetDisablePendingMessage() bool {
	return n.DisablePendingMessage
}

func (n *NotifierBase) GetFrequency() time.Duration {
	return n.Frequency
}
