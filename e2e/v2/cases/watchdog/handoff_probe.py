#!/usr/bin/python3
"""A harmless native descriptor canary, not a service/authentication fixture."""

import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

if sys.argv[1:3] == ["probe", "descriptors"]:
    params = json.loads(Path(sys.argv[sys.argv.index("--request") + 1]).read_bytes())
    binding, endpoint, other = (params[key] for key in ("binding_fd", "socket_fd", "other_fd"))
else:
    binding, endpoint, other = map(int, sys.argv[1:])
data = os.pread(binding, 1024 * 1024, 0)
closed = False
try:
    os.fstat(other)
except OSError as error:
    if error.errno != errno.EBADF:
        raise
    closed = True
print(json.dumps({"binding_sha256": hashlib.sha256(data).hexdigest(),
                  "socket": stat.S_ISSOCK(os.fstat(endpoint).st_mode), "other_closed": closed}))
