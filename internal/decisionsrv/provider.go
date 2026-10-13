package decisionsrv

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

type embeddingProvider struct {
	name, model, endpoint, host, key string
	dimension, batchSize             int
	timeout                          time.Duration
}

var variablePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var fakeFeatures = regexp.MustCompile(`[a-z0-9_]+(?:-[a-z0-9_]+)*|[\x{3400}-\x{9fff}]`)

var providerReads atomic.Int64

func providerFromConfig(path string) (*embeddingProvider, error) {
	providerReads.Add(1)
	config := object{"provider": "none"}
	if path != "" {
		text, e := readRegular(path, 64<<10)
		if e != nil {
			return nil, invalid("cannot read embedding config file")
		}
		v, e := parseJSON([]byte(text))
		if e != nil {
			return nil, e
		}
		config = obj(v)
	}
	if config == nil {
		return nil, invalid("embedding config must be an object")
	}
	name := str(config["provider"])
	if name == "" || name == "none" {
		return nil, providerFailure("embedding provider is disabled (none); no text was sent")
	}
	if name != "fake" && name != "voyage" {
		return nil, invalid("unsupported embedding provider")
	}
	for k := range config {
		if !wordsSet("provider model dimension api_key_env endpoint batch_size timeout")[k] {
			return nil, invalid("unsupported embedding config field; never put a key in config")
		}
	}
	p := &embeddingProvider{name: name, model: "fake-v1", dimension: 128, batchSize: 64, timeout: 30 * time.Second, host: "local"}
	if name == "voyage" {
		p.model = "voyage-4-large"
		p.dimension = 1024
		p.endpoint = "https://api.voyageai.com/v1/embeddings"
	}
	if v, ok := config["model"]; ok {
		p.model = str(v)
	}
	if strings.TrimSpace(p.model) == "" || len([]rune(p.model)) > 200 {
		return nil, invalid("config.model must be a nonempty string")
	}
	if v, ok := config["dimension"]; ok {
		n, ok := integer(v)
		if !ok || n < 1 || n > 4096 {
			return nil, invalid("config.dimension must be an integer from 1 to 4096")
		}
		p.dimension = int(n)
	}
	if name == "voyage" && p.dimension != 256 && p.dimension != 512 && p.dimension != 1024 && p.dimension != 2048 {
		return nil, invalid("config.dimension must be 256, 512, 1024 or 2048")
	}
	if v, ok := config["batch_size"]; ok {
		n, ok := integer(v)
		if !ok || n < 1 || n > 1000 {
			return nil, invalid("config.batch_size must be an integer from 1 to 1000")
		}
		p.batchSize = int(n)
	}
	if v, ok := config["timeout"]; ok {
		n, ok := number(v)
		if !ok || n <= 0 || n > 120 {
			return nil, invalid("config.timeout must be between 0 and 120 seconds")
		}
		p.timeout = time.Duration(n * float64(time.Second))
	}
	if name == "voyage" {
		if v, ok := config["endpoint"]; ok {
			p.endpoint = str(v)
		}
		u, e := url.Parse(p.endpoint)
		if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") {
			return nil, invalid("config.endpoint requires HTTPS or loopback HTTP, without credentials")
		}
		if port := u.Port(); port != "" {
			if _, e := net.LookupPort("tcp", port); e != nil {
				return nil, invalid("config.endpoint requires HTTPS or loopback HTTP, without credentials")
			}
		}
		p.host = u.Hostname()
		variable := str(config["api_key_env"])
		if !variablePattern.MatchString(variable) {
			return nil, invalid("config.api_key_env must name an environment variable")
		}
		p.key = os.Getenv(variable)
		if p.key == "" || strings.ContainsAny(p.key, "\r\n\x00") {
			return nil, providerFailure("embedding API key is missing or invalid in the named environment variable")
		}
	}
	return p, nil
}
func (p *embeddingProvider) identity() string {
	s, _ := canonical(object{"name": p.name, "model": p.model, "dimension": p.dimension, "endpoint": p.endpoint})
	return s
}
func (p *embeddingProvider) checkQuery(query string) error {
	if p.name == "voyage" && len(query) > 24000 {
		return providerFailure("embedding text exceeds the conservative 24000-byte limit; nothing was sent")
	}
	return nil
}
func (p *embeddingProvider) fakeVector(text string) []float64 {
	features := fakeFeatures.FindAllString(casefold(text), -1)
	runes := []rune(text)
	for i := 0; i+1 < len(runes); i++ {
		if runes[i] >= 0x3400 && runes[i] <= 0x9fff && runes[i+1] >= 0x3400 && runes[i+1] <= 0x9fff {
			features = append(features, string(runes[i:i+2]))
		}
	}
	if len(features) == 0 {
		features = []string{text}
	}
	vector := make([]float64, p.dimension)
	for _, f := range features {
		h := sha256.Sum256([]byte(p.model + "\x00" + f))
		pos := int(binary.LittleEndian.Uint32(h[:4])) % p.dimension
		if h[4]&1 != 0 {
			vector[pos]++
		} else {
			vector[pos]--
		}
	}
	norm := vectorNorm(vector)
	if norm == 0 {
		vector[0] = 1
		norm = 1
	}
	for i := range vector {
		vector[i] /= norm
	}
	return vector
}
func (p *embeddingProvider) embed(query string) ([]float64, error) {
	if p.name == "fake" {
		return p.fakeVector(query), nil
	}
	body, e := canonical(object{"input": []string{query}, "model": p.model, "input_type": "query", "output_dimension": p.dimension, "output_dtype": "float", "truncation": false})
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequest("POST", p.endpoint, bytes.NewBufferString(body))
	if e != nil {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: p.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, providerFailure("embedding provider redirects are refused")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, providerFailure(fmt.Sprintf("embedding provider HTTP failure (status %d)", response.StatusCode))
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 64000001))
	if e != nil {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	if len(raw) > 64000000 {
		return nil, providerFailure("embedding response exceeds the size limit")
	}
	payload, e := parseJSON(raw)
	if e != nil {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	m := obj(payload)
	if m == nil {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	if model, ok := m["model"]; ok && model != p.model {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	data, ok := m["data"].([]any)
	if !ok || len(data) != 1 {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	item := obj(data[0])
	index, ok := integer(item["index"])
	if !ok || index != 0 {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	values, ok := item["embedding"].([]any)
	if !ok || len(values) != p.dimension {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	vector := make([]float64, len(values))
	nonzero := false
	for i, v := range values {
		n, ok := number(v)
		if !ok || !finite(n) || math.Abs(n) > math.MaxFloat32 {
			return nil, providerFailure("embedding provider request failed or returned invalid vectors")
		}
		vector[i] = n
		nonzero = nonzero || float32(n) != 0
	}
	if !nonzero {
		return nil, providerFailure("embedding provider request failed or returned invalid vectors")
	}
	return vector, nil
}
