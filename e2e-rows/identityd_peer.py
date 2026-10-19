"""A real connecting child for the Linux-only pidfd unit canary."""

import json
import os
import socket
import sys


def main():
    if sys.platform != "linux" or len(sys.argv) != 2:
        raise RuntimeError("the peer helper requires Linux and a Unix socket path")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.connect(sys.argv[1])
        print(json.dumps({"pid": os.getpid()}), flush=True)
        if sys.stdin.buffer.read(1) != b"q":
            raise RuntimeError("the peer helper did not receive its collection command")


if __name__ == "__main__":
    main()
