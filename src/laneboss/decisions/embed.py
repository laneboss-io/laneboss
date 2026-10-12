"""Explicit, audited embedding providers; no third-party runtime libraries.

Official documentation read on 2026-10-08:
https://docs.voyageai.com/docs/embeddings
https://docs.voyageai.com/reference/embeddings-api

The documented endpoint is POST https://api.voyageai.com/v1/embeddings with
Bearer authentication. The best general multilingual model is voyage-4-large:
32,000 tokens per text; 1024 dimensions by default, or 256, 512, 2048.
Input is a string list with model and input_type=document or query. Requests
allow at most 1,000 texts and, for this model, 120,000 total tokens. We request
float output with truncation=false. Without a tokenizer dependency we use
conservative UTF-8 byte ceilings: 24,000 per text and 80,000 per batch, leaving
room for provider-added prompts. These are intentionally below API limits.
The fake provider is feature hashing, not a semantic retrieval model.
"""

import hashlib
import http.client
import math
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .schema import IntegrityError, InvalidInput, ProviderError, canonical, parse_json, read_json
from .store import pack_vector, unpack_vector


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ProviderError("embedding provider redirects are refused")


class Provider:
    def __init__(self, config):
        if not isinstance(config, dict):
            raise InvalidInput("embedding config must be an object")
        name = config.get("provider", "none")
        if name == "none":
            raise ProviderError("embedding provider is disabled (none); no text was sent")
        if name not in ("fake", "voyage"):
            raise InvalidInput("unsupported embedding provider")
        if set(config) - {"provider", "model", "dimension", "api_key_env", "endpoint", "batch_size", "timeout"}:
            raise InvalidInput("unsupported embedding config field; never put a key in config")
        self.name = name
        self.model = config.get("model", "fake-v1" if name == "fake" else "voyage-4-large")
        if not isinstance(self.model, str) or not self.model.strip() or len(self.model) > 200:
            raise InvalidInput("config.model must be a nonempty string")
        self.dimension = config.get("dimension", 128 if name == "fake" else 1024)
        if type(self.dimension) is not int or not 1 <= self.dimension <= 4096:
            raise InvalidInput("config.dimension must be an integer from 1 to 4096")
        if name == "voyage" and self.dimension not in (256, 512, 1024, 2048):
            raise InvalidInput("config.dimension must be 256, 512, 1024 or 2048")
        self.batch_size = config.get("batch_size", 64)
        if type(self.batch_size) is not int or not 1 <= self.batch_size <= 1000:
            raise InvalidInput("config.batch_size must be an integer from 1 to 1000")
        self.timeout = config.get("timeout", 30)
        if type(self.timeout) not in (int, float) or not math.isfinite(self.timeout) or not 0 < self.timeout <= 120:
            raise InvalidInput("config.timeout must be between 0 and 120 seconds")
        self.host = "local"
        self.key = None
        if name == "voyage":
            self.endpoint = config.get("endpoint", "https://api.voyageai.com/v1/embeddings")
            try:
                endpoint = urlsplit(self.endpoint)
                endpoint.port
                if (not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query
                        or endpoint.fragment or endpoint.scheme not in ("http", "https")):
                    raise ValueError()
                if endpoint.scheme == "http" and endpoint.hostname not in ("127.0.0.1", "localhost", "::1"):
                    raise ValueError()
            except (ValueError, TypeError, AttributeError) as error:
                raise InvalidInput("config.endpoint requires HTTPS or loopback HTTP, without credentials") from error
            self.host = endpoint.hostname
            variable = config.get("api_key_env")
            if not isinstance(variable, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", variable):
                raise InvalidInput("config.api_key_env must name an environment variable")
            self.key = os.environ.get(variable)
            if not self.key or any(character in self.key for character in "\r\n\x00"):
                raise ProviderError("embedding API key is missing or invalid in the named environment variable")

    def batches(self, items):
        pending = []
        size = 0
        for item in items:
            item_size = len(item["text"].encode("utf-8"))
            if self.name == "voyage" and item_size > 24000:
                raise ProviderError("embedding text exceeds the conservative 24000-byte limit; nothing was sent")
            if pending and (len(pending) >= self.batch_size or (self.name == "voyage" and size + item_size > 80000)):
                yield pending
                pending = []
                size = 0
            pending.append(item)
            size += item_size
        if pending:
            yield pending

    def fake_vector(self, text):
        features = re.findall(r"[a-z0-9_]+(?:-[a-z0-9_]+)*|[\u3400-\u9fff]", text.casefold())
        features.extend(re.findall(r"(?=([\u3400-\u9fff]{2}))", text))
        if not features:
            features = [text]
        vector = [0.0] * self.dimension
        for feature in features:
            hashed = hashlib.sha256((self.model + "\x00" + feature).encode("utf-8")).digest()
            position = int.from_bytes(hashed[:4], "little") % self.dimension
            vector[position] += 1.0 if hashed[4] & 1 else -1.0
        norm = math.sqrt(sum(number * number for number in vector))
        if not norm:
            vector[0] = 1.0
            norm = 1.0
        return [number / norm for number in vector]

    def embed(self, texts, input_type):
        if self.name == "fake":
            return [self.fake_vector(text) for text in texts]
        body = {"input": texts, "model": self.model, "input_type": input_type,
                "output_dimension": self.dimension, "output_dtype": "float", "truncation": False}
        request = Request(self.endpoint, data=canonical(body).encode("utf-8"), method="POST",
                          headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
        opener = build_opener(ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read(64000001)
                if len(raw) > 64000000:
                    raise ProviderError("embedding response exceeds the size limit")
                payload = parse_json(raw.decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("model", self.model) != self.model:
                raise ValueError()
            data = payload["data"]
            if not isinstance(data, list) or len(data) != len(texts):
                raise ValueError()
            vectors = [None] * len(texts)
            for item in data:
                index = item["index"]
                if type(index) is not int or not 0 <= index < len(texts) or vectors[index] is not None:
                    raise ValueError()
                blob = pack_vector(item["embedding"], self.dimension)
                unpack_vector(blob, self.dimension)
                vectors[index] = item["embedding"]
            return vectors
        except ProviderError:
            raise
        except HTTPError as error:
            raise ProviderError("embedding provider HTTP failure (status {})".format(error.code)) from None
        except (http.client.HTTPException, URLError, OSError, ValueError, TypeError, KeyError, InvalidInput, ArithmeticError,
                IntegrityError):
            raise ProviderError("embedding provider request failed or returned invalid vectors") from None


def provider_from_config(path=None):
    return Provider(read_json(path) if path else {"provider": "none"})


def embed_store(store, provider):
    store.ensure_model(provider)
    existing = {}
    for row in store.connection.execute("SELECT * FROM vectors WHERE model = ?", (provider.model,)):
        store.checked_vector(row, provider.dimension)
        existing[(row["record_id"], row["which_text"])] = row["text_sha256"]
    pending = []
    total_sides = 0
    for row in store.rows():
        store.checked_record(row)
        total_sides += 2
        for side, hash_column in (("q_text", "q_sha256"), ("d_text", "d_sha256")):
            if existing.get((row["id"], side)) != row[hash_column]:
                pending.append({"record_id": row["id"], "which_text": side, "text": row[side]})
    batches = list(provider.batches(pending))
    embedded = 0
    for batch in batches:
        store.log_egress(batch, provider, "document")
        vectors = provider.embed([item["text"] for item in batch], "document")
        store.progress.sent += len(batch)
        store.save_vectors(batch, provider, vectors)
        embedded += len(batch)
    return {"model": provider.model, "embedded": embedded, "skipped": total_sides - len(pending)}


def embed_query(store, provider, query):
    batch = [{"record_id": None, "which_text": "query", "text": query}]
    list(provider.batches(batch))
    store.log_egress(batch, provider, "query")
    return provider.embed([query], "query")[0]
