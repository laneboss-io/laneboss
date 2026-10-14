package decisions

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
	"strconv"
	"strings"
	"time"
)

type provider struct {
	name, model, host, endpoint, key string
	dimension, batchSize             int
	timeout                          time.Duration
}

var envPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func providerFromConfig(path string) (*provider, error) {
	var value any = object{"provider": "none"}
	var e error
	if path != "" {
		value, e = readJSON(path)
		if e != nil {
			return nil, e
		}
	}
	m := obj(value)
	if m == nil {
		return nil, invalid("embedding config must be an object")
	}
	name := "none"
	if x, ok := m["provider"]; ok {
		name = str(x)
	}
	if name == "none" {
		return nil, providerError("embedding provider is disabled (none); no text was sent")
	}
	if !member(name, "fake voyage") {
		return nil, invalid("unsupported embedding provider")
	}
	if e = allowed(m, "provider model dimension api_key_env endpoint batch_size timeout", "embedding config"); e != nil {
		return nil, invalid("unsupported embedding config field; never put a key in config")
	}
	p := &provider{name: name, host: "local", batchSize: 64, timeout: 30 * time.Second}
	if name == "fake" {
		p.model = "fake-v1"
		p.dimension = 128
	} else {
		p.model = "voyage-4-large"
		p.dimension = 1024
	}
	if x, ok := m["model"]; ok {
		p.model = str(x)
	}
	if trimmed(p.model) == "" || len([]rune(p.model)) > 200 || strings.ContainsRune(p.model, 0) {
		return nil, invalid("config.model must be a nonempty string")
	}
	if x, ok := m["dimension"]; ok {
		n, ok := integer(x)
		if !ok || n < 1 || n > 4096 {
			return nil, invalid("config.dimension must be an integer from 1 to 4096")
		}
		p.dimension = int(n)
	}
	if name == "voyage" && p.dimension != 256 && p.dimension != 512 && p.dimension != 1024 && p.dimension != 2048 {
		return nil, invalid("config.dimension must be 256, 512, 1024 or 2048")
	}
	if x, ok := m["batch_size"]; ok {
		n, ok := integer(x)
		if !ok || n < 1 || n > 1000 {
			return nil, invalid("config.batch_size must be an integer from 1 to 1000")
		}
		p.batchSize = int(n)
	}
	if x, ok := m["timeout"]; ok {
		n, ok := number(x)
		if !ok || n <= 0 || n > 120 {
			return nil, invalid("config.timeout must be between 0 and 120 seconds")
		}
		p.timeout = time.Duration(n * float64(time.Second))
	}
	if name == "voyage" {
		p.endpoint = "https://api.voyageai.com/v1/embeddings"
		if x, ok := m["endpoint"]; ok {
			p.endpoint = str(x)
		}
		u, e := url.Parse(p.endpoint)
		if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !member(u.Scheme, "http https") || (u.Scheme == "http" && !member(strings.ToLower(u.Hostname()), "localhost 127.0.0.1 ::1")) {
			return nil, invalid("config.endpoint requires HTTPS or loopback HTTP, without credentials")
		}
		if port := u.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 0 || n > 65535 {
				return nil, invalid("config.endpoint requires HTTPS or loopback HTTP, without credentials")
			}
		}
		if strings.HasPrefix(u.Host, "[") {
			host, _, _ := strings.Cut(u.Hostname(), "%")
			if !strings.Contains(host, ":") || net.ParseIP(host) == nil {
				return nil, invalid("config.endpoint requires HTTPS or loopback HTTP, without credentials")
			}
		}
		p.host = strings.ToLower(u.Hostname())
		variable := str(m["api_key_env"])
		if !envPattern.MatchString(variable) {
			return nil, invalid("config.api_key_env must name an environment variable")
		}
		p.key = os.Getenv(variable)
		if p.key == "" || strings.ContainsAny(p.key, "\r\n\x00") {
			return nil, providerError("embedding API key is missing or invalid in the named environment variable")
		}
	}
	return p, nil
}
func (p *provider) batches(items []object) ([][]object, error) {
	out := [][]object{}
	pending := []object{}
	size := 0
	for _, item := range items {
		n := len(str(item["text"]))
		if p.name == "voyage" && n > 24000 {
			return nil, providerError("embedding text exceeds the conservative 24000-byte limit; nothing was sent")
		}
		if len(pending) > 0 && (len(pending) >= p.batchSize || (p.name == "voyage" && size+n > 80000)) {
			out = append(out, pending)
			pending = []object{}
			size = 0
		}
		pending = append(pending, item)
		size += n
	}
	if len(pending) > 0 {
		out = append(out, pending)
	}
	return out, nil
}

var featurePattern = regexp.MustCompile(`[a-z0-9_]+(?:-[a-z0-9_]+)*|[\x{3400}-\x{9fff}]`)

func (p *provider) fakeVector(text string) []any {
	features := featurePattern.FindAllString(casefold(text), -1)
	r := []rune(text)
	for i := 0; i+1 < len(r); i++ {
		if r[i] >= 0x3400 && r[i] <= 0x9fff && r[i+1] >= 0x3400 && r[i+1] <= 0x9fff {
			features = append(features, string(r[i:i+2]))
		}
	}
	if len(features) == 0 {
		features = []string{text}
	}
	v := make([]float64, p.dimension)
	for _, feature := range features {
		h := sha256.Sum256([]byte(p.model + "\x00" + feature))
		index := int(binary.LittleEndian.Uint32(h[:4]) % uint32(p.dimension))
		if h[4]&1 != 0 {
			v[index]++
		} else {
			v[index]--
		}
	}
	norm := 0.0
	for _, n := range v {
		norm += n * n
	}
	norm = math.Sqrt(norm)
	if norm == 0 {
		v[0] = 1
		norm = 1
	}
	out := make([]any, len(v))
	for i, n := range v {
		out[i] = n / norm
	}
	return out
}
func (p *provider) embed(texts []string, inputType string) ([][]any, error) {
	if p.name == "fake" {
		out := make([][]any, len(texts))
		for i, text := range texts {
			out[i] = p.fakeVector(text)
		}
		return out, nil
	}
	body := object{"input": texts, "model": p.model, "input_type": inputType, "output_dimension": p.dimension, "output_dtype": "float", "truncation": false}
	req, e := http.NewRequest(http.MethodPost, p.endpoint, bytes.NewBufferString(canonical(body)))
	if e != nil {
		return nil, providerError("embedding provider request failed or returned invalid vectors")
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: p.timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	res, e := client.Do(req)
	if e != nil {
		return nil, providerError("embedding provider request failed or returned invalid vectors")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return nil, providerError("embedding provider redirects are refused")
	}
	if res.StatusCode >= 400 {
		return nil, providerError(fmt.Sprintf("embedding provider HTTP failure (status %d)", res.StatusCode))
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, 64000001))
	if e != nil {
		return nil, providerError("embedding provider request failed or returned invalid vectors")
	}
	if len(raw) > 64000000 {
		return nil, providerError("embedding response exceeds the size limit")
	}
	v, e := parseJSON(raw)
	if e != nil {
		return nil, providerError("embedding provider request failed or returned invalid vectors")
	}
	m := obj(v)
	bad := func() ([][]any, error) {
		return nil, providerError("embedding provider request failed or returned invalid vectors")
	}
	if m == nil {
		return bad()
	}
	if x, ok := m["model"]; ok && x != p.model {
		return bad()
	}
	data, ok := m["data"].([]any)
	if !ok || len(data) != len(texts) {
		return bad()
	}
	out := make([][]any, len(texts))
	for _, item := range data {
		o := obj(item)
		index, ok := integer(o["index"])
		if !ok || index < 0 || index >= int64(len(texts)) || out[index] != nil {
			return bad()
		}
		blob, e := packVector(o["embedding"], p.dimension)
		if e != nil {
			return bad()
		}
		if _, e = unpackVector(blob, p.dimension); e != nil {
			return bad()
		}
		out[index] = list(o["embedding"])
	}
	return out, nil
}
func (s *store) ensureModel(p *provider) error {
	v := object{"model": p.model, "provider": p.name, "dimension": p.dimension}
	v["entry_sha256"] = entryHash(v)
	old, e := s.one("SELECT * FROM models WHERE model = ?", p.model)
	if e != nil {
		return e
	}
	if old != nil {
		if e = checkedModel(old); e != nil {
			return e
		}
		if !equal(old, v) {
			return invalid("model already exists with different provider or dimension")
		}
		return nil
	}
	created := false
	e = s.transaction(func() error {
		old, e := s.one("SELECT * FROM models WHERE model = ?", p.model)
		if e != nil {
			return e
		}
		if old != nil {
			if e = checkedModel(old); e != nil {
				return e
			}
			if !equal(old, v) {
				return invalid("model already exists with different provider or dimension")
			}
			return nil
		}
		if e = s.insertMapping("models", modelColumns, v); e != nil {
			return e
		}
		created = true
		return nil
	})
	if e == nil && created {
		s.progress.model = p.model
	}
	return e
}
func (s *store) logEgress(items []object, p *provider, inputType string) error {
	e := s.transaction(func() error {
		previous, e := s.one("SELECT entry_sha256 FROM egress_log ORDER BY id DESC LIMIT 1")
		if e != nil {
			return e
		}
		h := str(previous["entry_sha256"])
		id, e := s.count("SELECT coalesce(max(id), 0) + 1 FROM egress_log")
		if e != nil {
			return e
		}
		for i, item := range items {
			v := object{"id": id + i, "record_id": item["record_id"], "which_text": item["which_text"], "text": item["text"], "text_sha256": digest(item["text"]), "model": p.model, "at": now(), "endpoint_host": p.host, "input_type": inputType, "previous_entry_sha256": h}
			v["entry_sha256"] = entryHash(v)
			if e = s.insertMapping("egress_log", egressColumns, v); e != nil {
				return e
			}
			h = str(v["entry_sha256"])
		}
		return nil
	})
	if e == nil {
		s.progress.receipts += len(items)
	}
	return e
}
func (s *store) saveVectors(items []object, p *provider, vectors [][]any) error {
	if len(items) != len(vectors) {
		return providerError("embedding provider request failed or returned invalid vectors")
	}
	e := s.transaction(func() error {
		for i, item := range items {
			blob, e := packVector(vectors[i], p.dimension)
			if e != nil {
				return e
			}
			if _, e = unpackVector(blob, p.dimension); e != nil {
				return e
			}
			v := object{"record_id": item["record_id"], "which_text": item["which_text"], "model": p.model, "dimension": p.dimension, "text": item["text"], "text_sha256": digest(item["text"]), "vector": blob, "vector_sha256": digest(blob), "created_at": now()}
			v["entry_sha256"] = entryHash(v)
			if _, e = s.exec("DELETE FROM vectors WHERE record_id = ? AND which_text = ? AND model = ?", item["record_id"], item["which_text"], p.model); e != nil {
				return e
			}
			if e = s.insertMapping("vectors", vectorColumns, v); e != nil {
				return e
			}
		}
		return nil
	})
	if e == nil {
		s.progress.vectors += len(items)
	}
	return e
}
func (s *store) embedStore(p *provider) (object, error) {
	if e := s.ensureModel(p); e != nil {
		return nil, e
	}
	existing := map[string]string{}
	rows, e := s.query("SELECT * FROM vectors WHERE model = ?", p.model)
	if e != nil {
		return nil, e
	}
	for _, r := range rows {
		if _, e = checkedVector(r, p.dimension); e != nil {
			return nil, e
		}
		existing[canonical([]any{r["record_id"], r["which_text"]})] = str(r["text_sha256"])
	}
	pending := []object{}
	rows, e = s.query("SELECT * FROM records ORDER BY id")
	if e != nil {
		return nil, e
	}
	for _, r := range rows {
		if _, e = s.checkedRecord(r); e != nil {
			return nil, e
		}
		for _, side := range []string{"q_text", "d_text"} {
			column := "q_sha256"
			if side == "d_text" {
				column = "d_sha256"
			}
			if existing[canonical([]any{r["id"], side})] != r[column] {
				pending = append(pending, object{"record_id": r["id"], "which_text": side, "text": r[side]})
			}
		}
	}
	batches, e := p.batches(pending)
	if e != nil {
		return nil, e
	}
	embedded := 0
	for _, batch := range batches {
		if e = s.logEgress(batch, p, "document"); e != nil {
			return nil, e
		}
		texts := []string{}
		for _, item := range batch {
			texts = append(texts, str(item["text"]))
		}
		vectors, e := p.embed(texts, "document")
		if e != nil {
			return nil, e
		}
		s.progress.sent += len(batch)
		if e = s.saveVectors(batch, p, vectors); e != nil {
			return nil, e
		}
		embedded += len(batch)
	}
	return object{"model": p.model, "embedded": embedded, "skipped": len(rows)*2 - len(pending)}, nil
}
func (s *store) embedQuery(p *provider, query string) ([]float64, error) {
	batch := []object{{"record_id": nil, "which_text": "query", "text": query}}
	if _, e := p.batches(batch); e != nil {
		return nil, e
	}
	if e := s.logEgress(batch, p, "query"); e != nil {
		return nil, e
	}
	vectors, e := p.embed([]string{query}, "query")
	if e != nil {
		return nil, e
	}
	a := make([]float64, len(vectors[0]))
	for i, x := range vectors[0] {
		n, ok := number(x)
		if !ok {
			return nil, providerError("embedding provider request failed or returned invalid vectors")
		}
		a[i] = n
	}
	return a, nil
}
