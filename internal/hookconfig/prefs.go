package hookconfig

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

func vetPrefs(envHome, accountHome string) error {
	for _, home := range []string{envHome, accountHome} {
		if !filepath.IsAbs(home) {
			return trustError("account preference home", "Codex account preferences cannot be located")
		}
		if err := systemPrefs(home); err != nil {
			return err
		}
	}
	return nil
}

func prefDirectory(home string) error {
	directory := filepath.Join(home, "Library", "Preferences")
	for _, name := range []string{"com.openai.codex.plist", ".GlobalPreferences.plist"} {
		if err := inspectPlist(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	byHost := filepath.Join(directory, "ByHost")
	entries, err := os.ReadDir(byHost)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return trustError(byHost, "Codex ByHost preferences cannot be read")
	}
	for _, entry := range entries {
		if (strings.HasPrefix(entry.Name(), "com.openai.codex.") || strings.HasPrefix(entry.Name(), ".GlobalPreferences.")) && strings.HasSuffix(entry.Name(), ".plist") {
			if err := inspectPlist(filepath.Join(byHost, entry.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func inspectPlist(path string) (err error) {
	defer func() {
		if err != nil {
			err = trustError(path, err.Error())
		}
	}()
	if info, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil || info.Mode().Perm()&0444 == 0 {
		return errors.New("Codex preferences cannot be read")
	}
	data, err := regularBytes(path)
	if err != nil {
		return err
	}
	if bytes.HasPrefix(data, []byte("bplist")) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "--", "-")
		cmd.Stdin = bytes.NewReader(data)
		cmd.Stderr = io.Discard
		cmd.WaitDelay = time.Second
		var output probeOutput
		cmd.Stdout = &output
		if cmd.Run() != nil || output.overflow {
			return errors.New("Codex binary preferences cannot be decoded")
		}
		data = output.Bytes()
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	token, err := plistToken(decoder)
	root, ok := token.(xml.StartElement)
	if err != nil || !ok || root.Name.Local != "plist" || root.Name.Space != "" {
		return errors.New("Codex preferences are not a plist")
	}
	for _, attribute := range root.Attr {
		if attribute.Name.Space != "" || attribute.Name.Local != "version" || attribute.Value != "1.0" || len(root.Attr) != 1 {
			return errors.New("Codex preference plist attributes cannot be vetted")
		}
	}
	token, err = plistToken(decoder)
	value, ok := token.(xml.StartElement)
	if err != nil || !ok || value.Name.Local != "dict" {
		return errors.New("Codex preferences must be a plist dictionary")
	}
	if err := plistValue(decoder, value, 0); err != nil {
		return err
	}
	token, err = plistToken(decoder)
	end, ok := token.(xml.EndElement)
	if err != nil || !ok || end.Name != root.Name {
		return errors.New("Codex preferences have an invalid plist root")
	}
	if _, err := plistToken(decoder); err != io.EOF {
		return errors.New("Codex preferences contain trailing content")
	}
	return nil
}

func plistToken(decoder *xml.Decoder) (xml.Token, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch node := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(node)) != "" {
				return nil, errors.New("Codex preferences contain unexpected text")
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
		default:
			return token, nil
		}
	}
}

func plistText(decoder *xml.Decoder, start xml.StartElement) (string, error) {
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", errors.New("Codex preference value cannot be decoded")
		}
		switch node := token.(type) {
		case xml.CharData:
			text.Write(node)
		case xml.Comment:
		case xml.EndElement:
			if node.Name == start.Name {
				return text.String(), nil
			}
			return "", errors.New("Codex preference value has an invalid end")
		default:
			return "", errors.New("Codex preference scalar contains nested content")
		}
	}
}

func plistValue(decoder *xml.Decoder, start xml.StartElement, depth int) error {
	if depth > 64 || start.Name.Space != "" || len(start.Attr) != 0 {
		return errors.New("Codex preference structure cannot be vetted")
	}
	if start.Name.Local != "dict" && start.Name.Local != "array" {
		switch start.Name.Local {
		case "string", "data", "date", "integer", "real", "true", "false":
			text, err := plistText(decoder, start)
			if err != nil {
				return err
			}
			if (start.Name.Local == "true" || start.Name.Local == "false") && strings.TrimSpace(text) != "" {
				return errors.New("Codex preference boolean has unexpected text")
			}
			switch start.Name.Local {
			case "integer":
				if _, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64); err != nil {
					return errors.New("Codex preference integer cannot be decoded")
				}
			case "real":
				if _, err := strconv.ParseFloat(strings.TrimSpace(text), 64); err != nil {
					return errors.New("Codex preference real cannot be decoded")
				}
			case "date":
				if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(text)); err != nil {
					return errors.New("Codex preference date cannot be decoded")
				}
			case "data":
				if _, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), "")); err != nil {
					return errors.New("Codex preference data cannot be decoded")
				}
			}
			return nil
		default:
			return errors.New("Codex preference type cannot be vetted")
		}
	}
	keys := map[string]bool{}
	for {
		token, err := plistToken(decoder)
		if err != nil {
			return errors.New("Codex preference collection cannot be decoded")
		}
		if end, ok := token.(xml.EndElement); ok && end.Name == start.Name {
			return nil
		}
		child, ok := token.(xml.StartElement)
		if !ok {
			return errors.New("Codex preference collection has unexpected content")
		}
		if start.Name.Local == "dict" {
			if child.Name.Local != "key" || child.Name.Space != "" || len(child.Attr) != 0 {
				return errors.New("Codex preference dictionary needs a key")
			}
			key, err := plistText(decoder, child)
			if err != nil || keys[key] {
				return errors.New("Codex preference key cannot be vetted")
			}
			keys[key] = true
			if strings.Contains(strings.ToLower(key), "hook") || key == "managed_dir" || key == "project_root_markers" {
				return errors.New("Codex preferences contain unvetted hook keys: " + strconv.Quote(key))
			}
			if permissionKey(key) || sandboxKey(key) || key == "agents" || agentFeature(key) {
				return errors.New("Codex preferences contain unvetted permission key " + strconv.Quote(key))
			}
			token, err = plistToken(decoder)
			child, ok = token.(xml.StartElement)
			if err != nil || !ok {
				return errors.New("Codex preference key has no value")
			}
			if key == "approval_policy" {
				if child.Name.Local != "string" || child.Name.Space != "" || len(child.Attr) != 0 {
					return errors.New("Codex preference approval_policy cannot be vetted")
				}
				policy, err := plistText(decoder, child)
				if err != nil || policy != "never" {
					return errors.New("Codex preference approval_policy must be never")
				}
				continue
			}
			if key == "config_toml_base64" || key == "requirements_toml_base64" {
				if child.Name.Local != "string" || child.Name.Space != "" || len(child.Attr) != 0 {
					return errors.New("Codex encoded preferences must be strings")
				}
				encoded, err := plistText(decoder, child)
				if err != nil {
					return err
				}
				if err := plistConfig(encoded); err != nil {
					return err
				}
				continue
			}
		}
		if err := plistValue(decoder, child, depth+1); err != nil {
			return err
		}
	}
}

func plistConfig(encoded string) error {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !utf8.Valid(data) {
		return errors.New("Codex encoded preference config cannot be decoded")
	}
	document := map[string]any{}
	if _, err := toml.Decode(string(data), &document); err != nil {
		return errors.New("Codex encoded preference config contains invalid TOML")
	}
	if foreignHooks(document, "") {
		return errors.New("Codex encoded preference config contains unvetted hook keys: " + blockedKey(document, ""))
	}
	return nil
}
