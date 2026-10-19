package boxrun

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

const (
	maxEntries = 200000
	maxFile    = int64(2 << 30)
	maxTotal   = int64(8 << 30)
)

type harvestInfo struct {
	files    int
	bytes    int64
	manifest string
	names    map[string]bool
}

func cleanTarName(name string) (string, error) {
	if name == "" || path.IsAbs(name) || strings.ContainsAny(name, "\x00\\\n\r") {
		return "", fmt.Errorf("boxrun: unsafe tar path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("boxrun: parent segment in tar path %q", name)
		}
	}
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	name = path.Clean(name)
	if name == "." || name == "" || path.IsAbs(name) {
		return "", errors.New("boxrun: empty tar path")
	}
	return name, nil
}

func openOutput(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("boxrun: output root must be a directory, without a link")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if err := root.Chmod(".", 0700); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

func makeDirs(root *os.Root, name string) error {
	if name == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(name, "/") {
		current = path.Join(current, part)
		if err := root.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("boxrun: non-directory component %q", current)
		}
		if err := root.Chmod(current, 0700); err != nil {
			return err
		}
	}
	return nil
}

func extractTar(input io.Reader, dir string) (info harvestInfo, err error) {
	return extractLimited(input, dir, maxEntries, maxFile, maxTotal)
}

func extractLimited(input io.Reader, dir string, entryLimit int,
	fileLimit, totalLimit int64) (info harvestInfo, err error) {
	info.names = make(map[string]bool)
	root, err := openOutput(dir)
	if err != nil {
		return info, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	reader := tar.NewReader(input)
	entries := 0
	for {
		header, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			return info, nil
		}
		if readErr != nil {
			return info, readErr
		}
		entries++
		if entries > entryLimit {
			return info, errors.New("boxrun: too many tar entries")
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		default:
			return info, fmt.Errorf("boxrun: refused tar entry type %d", header.Typeflag)
		}
		if header.Size < 0 || header.Size > fileLimit || header.Size > totalLimit-info.bytes {
			return info, errors.New("boxrun: tar size limit exceeded")
		}
		if header.Typeflag == tar.TypeDir && header.Size != 0 {
			return info, errors.New("boxrun: directory carries file data")
		}
		// tar -C OUT -cf - . includes its root directory as ./.
		if header.Typeflag == tar.TypeDir && (header.Name == "." || header.Name == "./") {
			continue
		}
		name, nameErr := cleanTarName(header.Name)
		if nameErr != nil {
			return info, nameErr
		}
		if header.Typeflag == tar.TypeDir {
			if err := makeDirs(root, name); err != nil {
				return info, err
			}
			continue
		}
		if err := makeDirs(root, path.Dir(name)); err != nil {
			return info, err
		}
		// Exclusive creation also refuses duplicates and existing final links.
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return info, err
		}
		count, copyErr := io.CopyN(file, reader, header.Size)
		closeErr := file.Close()
		info.bytes += count
		if err := errors.Join(copyErr, closeErr); err != nil {
			return info, err
		}
		info.files++
		info.names[name] = true
	}
}

func openRegular(root *os.Root, name string) (*os.File, error) {
	parts := strings.Split(name, "/")
	current := ""
	for i, part := range parts {
		current = path.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || i < len(parts)-1 && !info.IsDir() ||
			i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("boxrun: unsafe extracted file %q", name)
		}
	}
	return root.Open(name)
}

func verifyManifest(dir string, info harvestInfo) (digest string, err error) {
	return verifyManifestCtx(context.Background(), dir, info)
}

func verifyManifestCtx(ctx context.Context, dir string, info harvestInfo) (digest string, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	manifest, err := openRegular(root, "manifest.sha256")
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, manifest.Close()) }()
	hash := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(contextReader{ctx: ctx, input: manifest}, hash))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	listed := make(map[string]bool)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return "", errors.New("boxrun: malformed manifest line")
		}
		expected, err := hex.DecodeString(line[:64])
		if err != nil || len(expected) != sha256.Size {
			return "", errors.New("boxrun: invalid manifest hash")
		}
		name, err := cleanTarName(line[66:])
		if err != nil {
			return "", err
		}
		if listed[name] || name == "manifest.sha256" || name == ".complete" || !info.names[name] {
			return "", fmt.Errorf("boxrun: invalid manifest file %q", name)
		}
		file, err := openRegular(root, name)
		if err != nil {
			return "", err
		}
		fileHash := sha256.New()
		_, copyErr := io.Copy(fileHash, contextReader{ctx: ctx, input: file})
		if err := errors.Join(copyErr, file.Close()); err != nil {
			return "", err
		}
		if !strings.EqualFold(hex.EncodeToString(fileHash.Sum(nil)), line[:64]) {
			return "", fmt.Errorf("boxrun: manifest hash mismatch for %q", name)
		}
		listed[name] = true
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	for name := range info.names {
		if name != "manifest.sha256" && name != ".complete" && !listed[name] {
			return "", fmt.Errorf("boxrun: unlisted harvested file %q", name)
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *service) harvest(ctx context.Context, tr boxcore.Transport, out, dir string,
	allowChanged bool) (harvestInfo, error) {
	reader, writer := io.Pipe()
	type answer struct {
		info harvestInfo
		err  error
	}
	finished := make(chan answer, 1)
	received := false
	defer func() {
		// Pipe Close returns nil; also join the reader after an Exec panic.
		writer.Close()
		if !received {
			<-finished
		}
	}()
	go func() {
		info, err := extractTar(reader, dir)
		if err == nil {
			// tar has padding after its end marker; consume it so Exec can finish.
			_, err = io.Copy(io.Discard, reader)
		}
		closeErr := reader.CloseWithError(err)
		finished <- answer{info: info, err: errors.Join(err, closeErr)}
	}()
	code, execErr := execBound(ctx, tr, harvestCommand(out), nil, writer, s.d.Err, 2*time.Minute)
	closeErr := writer.CloseWithError(execErr)
	extracted := <-finished
	received = true
	err := errors.Join(execErr, closeErr, extracted.err)
	if code != 0 && !(code == 1 && allowChanged) {
		err = errors.Join(err, fmt.Errorf("boxrun: harvest tar exit %d", code))
	}
	if err != nil {
		return extracted.info, err
	}
	digest, err := verifyManifestCtx(ctx, dir, extracted.info)
	if err != nil {
		return extracted.info, err
	}
	extracted.info.manifest = digest
	return extracted.info, nil
}

type contextReader struct {
	ctx   context.Context
	input io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.input.Read(data)
}
