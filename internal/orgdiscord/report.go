package orgdiscord

import "time"

// OpenReportClient resolves the configured bot secret within this package.
// Report callers never receive the token or any credential-bearing headers.
func OpenReportClient(org string) (*Client, error) {
	files, err := openOrg(org)
	if err != nil {
		return nil, err
	}
	defer files.close()
	discord, store, err := settings(files)
	if err != nil {
		return nil, err
	}
	token, err := loadToken(discord, store)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(token, nil)
	if err != nil {
		return nil, err
	}
	client.rest.client.Timeout = 10 * time.Second
	return client, nil
}
