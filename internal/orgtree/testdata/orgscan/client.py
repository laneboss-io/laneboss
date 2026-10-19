"""HTTP client with typed errors and safe URL construction."""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener


class ClientError(Exception):
    def __init__(self, status, document):
        super().__init__(str(document.get("error", {}).get("message", "request failed")))
        self.status = status
        self.document = document


class Client:
    def __init__(self, url, token=None, timeout=10):
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("server URL must be HTTP or HTTPS")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("server URL must not contain credentials, query or fragment")
        self.url = url.rstrip("/")
        auth_value = token
        self.token = auth_value
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}))

    def request(self, method, path, body=None, query=None):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("request path must be server-relative")
        url = self.url + path
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                return None if not raw else json.loads(raw)
        except HTTPError as error:
            with error:
                try:
                    document = json.loads(error.read())
                except ValueError:
                    document = {"error": {"message": "server returned a non-JSON error"}}
                raise ClientError(error.code, document) from None
        except URLError:
            raise ClientError(0, {"error": {"message": "server is unavailable"}}) from None

    def register(self, username, password):
        return self.request("POST", "/auth/register", {"username": username, "password": password})

    def login(self, username, password):
        answer = self.request("POST", "/auth/login", {"username": username, "password": password})
        self.token = answer["token"]
        return answer

    def logout(self):
        answer = self.request("POST", "/auth/logout", {})
        self.token = None
        return answer

    def list_tasks(self, status=None):
        return self.request("GET", "/tasks", query={"status": status})

    def get_task(self, task_id):
        return self.request("GET", "/tasks/" + str(task_id))

    def create_task(self, title, description="", priority=3):
        return self.request("POST", "/tasks", {"title": title, "description": description, "priority": priority})

    def update_task(self, task_id, values):
        return self.request("PATCH", "/tasks/" + str(task_id), values)

    def delete_task(self, task_id):
        return self.request("DELETE", "/tasks/" + str(task_id))
