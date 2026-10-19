package messaging

import (
	"encoding/json"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
)

// These decoders validate result bodies, not endpoint authentication. The
// client still owns framing, binding and request correlation. Malformed remote
// data is an integrity failure and never returns a partially decoded result.
func DecodeMailResult(raw json.RawMessage) (api.Mail, error) {
	var mail api.Mail
	if err := decodeBody(raw, &mail); err != nil {
		return api.Mail{}, problem(api.CodeIntegrity, "mail result does not match the frozen schema")
	}
	if err := validStoredMail(mail); err != nil {
		return api.Mail{}, err
	}
	return mail, nil
}

func DecodeMailPageResult(raw json.RawMessage) (api.MailPage, error) {
	var page api.MailPage
	if err := decodeBody(raw, &page); err != nil {
		return api.MailPage{}, problem(api.CodeIntegrity, "mailbox result does not match the frozen schema")
	}
	if err := validMailPage(page); err != nil {
		return api.MailPage{}, err
	}
	return page, nil
}

func validMailPage(page api.MailPage) error {
	if page.Messages == nil || len(page.Messages) > 200 || len(page.Cursor) > maxCursor || !utf8.ValidString(page.Cursor) {
		return problem(api.CodeIntegrity, "mailbox result exceeds its array or cursor bounds")
	}
	seen := make(map[api.ID]bool)
	var previous api.Sequence
	for _, mail := range page.Messages {
		if err := validStoredMail(mail); err != nil {
			return err
		}
		if seen[mail.ID] || mail.QueuedSeq <= previous {
			return problem(api.CodeIntegrity, "mailbox result contains duplicate or unordered mail")
		}
		seen[mail.ID], previous = true, mail.QueuedSeq
	}
	return nil
}

func DecodeMailUploadResult(raw json.RawMessage) (api.BlobUpload, error) {
	var upload api.BlobUpload
	if err := decodeBody(raw, &upload); err != nil {
		return api.BlobUpload{}, problem(api.CodeIntegrity, "mail upload result does not match the frozen schema")
	}
	if !validID(upload.ObjectID) || upload.MaxChunkBytes < 1 || upload.MaxChunkBytes > api.MaxChunkBytes || !validTimestamp(upload.ExpiresAt) {
		return api.BlobUpload{}, problem(api.CodeIntegrity, "mail upload result has invalid identity, chunk bound or expiry")
	}
	return upload, nil
}

func DecodeMailBlobResult(raw json.RawMessage) (api.BlobRef, error) {
	var ref api.BlobRef
	if err := decodeBody(raw, &ref); err != nil {
		return api.BlobRef{}, problem(api.CodeIntegrity, "mail blob result does not match the frozen schema")
	}
	if err := validContent(ref); err != nil {
		return api.BlobRef{}, problem(api.CodeIntegrity, "mail blob result has invalid content identity or size")
	}
	return ref, nil
}
