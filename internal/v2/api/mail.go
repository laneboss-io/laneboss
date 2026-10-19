package api

type MailSendRequest struct {
	RecipientLifeID ID      `json:"recipient_life_id,omitempty"`
	ChannelGrantID  ID      `json:"channel_grant_id,omitempty"`
	Content         BlobRef `json:"content"`
	Ask             bool    `json:"ask"`
	ReplyTo         ID      `json:"reply_to,omitempty"`
}

type Mail struct {
	Generation      Generation      `json:"generation"`
	Artifacts       []BlobRef       `json:"artifacts"`
	Answer          *DecisionAnswer `json:"answer,omitempty"`
	ID              ID              `json:"id"`
	Sender          Actor           `json:"sender"`
	RecipientLifeID ID              `json:"recipient_life_id,omitempty"`
	ChannelGrantID  ID              `json:"channel_grant_id,omitempty"`
	Content         BlobRef         `json:"content"`
	Source          string          `json:"source"`
	QueuedSeq       Sequence        `json:"queued_seq"`
	LogicalTurnID   ID              `json:"logical_turn_id,omitempty"`
	Status          string          `json:"status"`
	Ask             bool            `json:"ask"`
	ReplyTo         ID              `json:"reply_to,omitempty"`
}

type MailReceipt struct {
	MailID        ID        `json:"mail_id"`
	Target        LifeRef   `json:"target"`
	LogicalTurnID ID        `json:"logical_turn_id"`
	Status        string    `json:"status"`
	PromptStatus  string    `json:"prompt_status"`
	Cause         string    `json:"cause"`
	ObservedAt    Timestamp `json:"observed_at"`
}

type MailPage struct {
	Messages []Mail `json:"messages"`
	Cursor   string `json:"cursor"`
}

type ReportRequest struct {
	Ask            bool      `json:"ask"`
	Content        BlobRef   `json:"content"`
	Artifacts      []BlobRef `json:"artifacts"`
	ChannelGrantID ID        `json:"channel_grant_id,omitempty"`
	ReplyTo        ID        `json:"reply_to,omitempty"`
}

type Delivery struct {
	Evidence        *ChannelSendEvidence `json:"evidence,omitempty"`
	ID              ID                   `json:"id"`
	MailID          ID                   `json:"mail_id"`
	ChannelID       ID                   `json:"channel_id"`
	Status          string               `json:"status"`
	RemoteReceiptID string               `json:"remote_receipt_id,omitempty"`
	Error           *Error               `json:"error,omitempty"`
}
