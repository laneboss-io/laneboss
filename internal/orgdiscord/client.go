package orgdiscord

import "net/http"

// Client exposes the existing Discord REST and channel-registration operations
// to other programs in this module. Credentials and HTTP headers remain private.
type Client struct{ rest *discordREST }

// NewClient creates the production REST client. decorate may wrap its transport
// for request policy or observation; nil leaves the production transport intact.
// Redirect handling, response bounds and sanitized errors are unchanged.
func NewClient(token string, decorate func(http.RoundTripper) http.RoundTripper) (*Client, error) {
	if !tokenPattern.MatchString(token) {
		return nil, refused("Discord credential is invalid")
	}
	api, err := newREST(token)
	if err != nil {
		return nil, err
	}
	if decorate != nil {
		transport := decorate(api.client.Transport)
		if transport == nil {
			api.client.CloseIdleConnections()
			return nil, refused("Discord transport wrapper returned no transport")
		}
		api.client.Transport = transport
	}
	return &Client{rest: api}, nil
}

// Request performs one request through the existing bounded REST implementation.
func (c *Client) Request(method, path string, body any) (map[string]any, error) {
	return c.rest.request(method, path, body, false)
}

// RegisterChannel registers an existing channel using the same validation,
// locking, persistence and verified hello as the channel add command.
func (c *Client) RegisterChannel(org, instance, channel string, members, roles []string) (map[string]any, error) {
	if !idPattern.MatchString(channel) {
		return nil, refused("channel must be a positive Discord id written as a string")
	}
	return addChannelClient(addArguments{org: org, instance: instance, channel: channel, members: members, groups: roles}, c.rest)
}

// VerifyMessage checks message identity, channel, exact content and bot authorship
// with the same verifier used by channel registration. Empty id accepts a new id.
func (c *Client) VerifyMessage(reply map[string]any, channel, text, id string) (string, error) {
	return verifyMessage(reply, Role{ChannelID: channel}, text, id)
}

// Close releases idle connections owned by the REST client.
func (c *Client) Close() { c.rest.client.CloseIdleConnections() }
