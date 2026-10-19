package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
)

// ReadFrame bounds allocation before reading a payload. On a Unix connection
// every byte is received with ancillary inspection, including the header.
func ReadFrame(reader io.Reader) ([]byte, error) {
	if connection, ok := reader.(*net.UnixConn); ok {
		reader = noAncillary{connection}
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > api.MaxFrameBytes {
		return nil, Invalid("frame length exceeds protocol bounds")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > api.MaxFrameBytes {
		return Invalid("frame length exceeds protocol bounds")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type noAncillary struct{ connection *net.UnixConn }

func (r noAncillary) Read(data []byte) (int, error) {
	oob := make([]byte, 65536)
	n, count, flags, _, err := r.connection.ReadMsgUnix(data, oob)
	if count != 0 {
		// Received FDs belong to this process even though the request is refused.
		// Close every delivered rights descriptor before returning the error.
		messages, parseErr := unix.ParseSocketControlMessage(oob[:count])
		var cleanupErr error
		for _, message := range messages {
			if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_RIGHTS {
				descriptors, rightsErr := unix.ParseUnixRights(&message)
				if rightsErr != nil {
					cleanupErr = errors.Join(cleanupErr, rightsErr)
					continue
				}
				for _, descriptor := range descriptors {
					cleanupErr = errors.Join(cleanupErr, unix.Close(descriptor))
				}
			}
		}
		if cleanupErr != nil {
			return 0, &api.Error{Code: api.CodeIntegrity, Message: "received descriptor cleanup failed",
				Instead: "Stop the connection and inspect descriptor containment."}
		}
		if parseErr != nil {
			return 0, Invalid("malformed ancillary data")
		}
		return 0, Invalid("ancillary data is forbidden")
	}
	if flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return 0, Invalid("truncated ancillary or frame data")
	}
	return n, err
}
