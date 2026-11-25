"""Bounded, opt-in HTTP targets and deterministic offline simulations."""
import json
import os
from typing import Protocol
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, ProxyHandler

from .suite import Case

MAX_RESPONSE = 1_000_000

class Target(Protocol):
    def respond(self, case: Case) -> str: ...


class DemoTarget:
    def __init__(self, vulnerable: bool = False):
        self.vulnerable = vulnerable

    def respond(self, case: Case) -> str:
        if self.vulnerable and case.forbidden:
            return " ".join(case.forbidden)
        return " ".join(case.required) if case.required else "Request declined."


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpTarget:
    def __init__(self, endpoint: str, adapter: str, model: str | None, timeout: float):
        parsed = urlsplit(endpoint)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (not parsed.hostname or parsed.username or parsed.password or parsed.fragment
                or parsed.scheme not in {"https", "http"}
                or (parsed.scheme == "http" and not local)):
            raise ValueError("Use HTTPS or an explicit localhost HTTP URL without credentials")
        if adapter not in {"generic", "chat"} or (adapter == "chat" and not model):
            raise ValueError("Chat adapter requires a model")
        if not 1 <= timeout <= 60:
            raise ValueError("Timeout must be between 1 and 60 seconds")
        self.endpoint, self.adapter, self.model, self.timeout = endpoint, adapter, model, timeout
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def respond(self, case: Case) -> str:
        if self.adapter == "chat":
            body = {"model": self.model, "messages": [{"role": "user", "content": case.prompt}]}
        else:
            body = {"prompt": case.prompt}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        token = os.environ.get("MODELAUDIT_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(self.endpoint, data=json.dumps(body).encode(), headers=headers, method="POST")
        with self.opener.open(request, timeout=self.timeout) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("Response exceeded size limit")
        payload = json.loads(raw)
        if self.adapter == "chat":
            value = payload["choices"][0]["message"]["content"]
        else:
            value = payload["response"]
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Target response must contain non-empty text")
        return value
