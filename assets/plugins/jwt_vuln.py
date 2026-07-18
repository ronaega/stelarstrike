"""
JWT vulnerability plugin.

Looks for a JWT in the Authorization header, cookies, or query string,
decodes it (without verifying, since we don't have the secret), and
checks for well-known weaknesses:
  - alg-none:            server accepts `{"alg":"none"}` with an empty signature
  - weak-secret:         HS256 token's signature is crackable against a small wordlist
  - kid-injection:       `kid` header looks path-traversal-able (informational flag)
  - expired-token-reuse: an expired token is still accepted by the server

Each check that requires sending a modified token back to the server is
gated by `engagement.allow_active_payloads`.
"""

from __future__ import annotations

import time

import jwt

from assets.core.report import Finding
from assets.plugins.base import VulnerabilityPlugin

_COMMON_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwtsecret", "your-256-bit-secret",
    "supersecret", "test", "admin", "key",
]


class JWTPlugin(VulnerabilityPlugin):
    id = "jwt"
    name = "JSON Web Token Vulnerabilities"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        token = await self._locate_token()
        if not token:
            return findings

        checks = self.options.get(
            "checks", ["alg-none", "weak-secret", "kid-injection", "expired-token-reuse"]
        )

        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return findings

        if "kid-injection" in checks:
            f = self._check_kid_injection(header, token)
            if f:
                findings.append(f)

        if "weak-secret" in checks and header.get("alg", "").startswith("HS"):
            f = self._check_weak_secret(token)
            if f:
                findings.append(f)

        if "alg-none" in checks and self.ctx.allow_active_payloads:
            f = await self._check_alg_none(token, payload)
            if f:
                findings.append(f)

        if "expired-token-reuse" in checks and self.ctx.allow_active_payloads:
            f = await self._check_expired_reuse(token, header, payload)
            if f:
                findings.append(f)

        return findings

    async def _locate_token(self) -> str | None:
        resp = await self.get(self.target_url)
        auth_header = resp.request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return auth_header.split(" ", 1)[1]
        for cookie_value in resp.cookies.values():
            if cookie_value.count(".") == 2:
                return cookie_value
        return None

    def _check_kid_injection(self, header: dict, token: str) -> Finding | None:
        kid = header.get("kid")
        if not kid:
            return None
        suspicious = any(s in str(kid) for s in ["..", "/", "\\", "http://", "https://", "' OR"])
        if suspicious:
            return self.finding(
                title="JWT 'kid' header looks injectable",
                url=self.target_url,
                parameter="kid",
                severity="high",
                confidence="low",
                evidence=f"kid='{kid}'",
                description=(
                    "The JWT 'kid' (Key ID) header contains characters consistent with "
                    "path traversal, SQL injection, or an attacker-controlled URL. If "
                    "the server uses 'kid' to look up the verification key (file path, "
                    "DB lookup, or URL fetch) without validation, an attacker may be "
                    "able to point verification at a key they control."
                ),
                remediation="Validate 'kid' against a strict allowlist of known key IDs; never use it directly in a file path, DB query, or URL fetch.",
                cwe="CWE-347",
            )
        return None

    def _check_weak_secret(self, token: str) -> Finding | None:
        for secret in _COMMON_WEAK_SECRETS:
            try:
                jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
            except jwt.InvalidSignatureError:
                continue
            except Exception:
                continue
            else:
                return self.finding(
                    title="JWT signed with a weak/common secret",
                    url=self.target_url,
                    severity="critical",
                    confidence="confirmed",
                    evidence="Signature validated against a common-secret wordlist (secret redacted from report).",
                    description=(
                        "The token's HMAC signature validates against a common weak "
                        "secret. Anyone with this secret can forge arbitrary tokens, "
                        "including ones with elevated privileges."
                    ),
                    remediation="Rotate the signing secret to a high-entropy value (>= 256 bits of randomness) and store it in a secrets manager, not source code.",
                    cwe="CWE-798",
                )
        return None

    async def _check_alg_none(self, token: str, payload: dict) -> Finding | None:
        forged = jwt.encode(payload, key="", algorithm="none")
        resp = await self.get(self.target_url, headers={"Authorization": f"Bearer {forged}"})
        if resp.status_code == 200:
            return self.finding(
                title="JWT 'alg: none' accepted by server",
                url=self.target_url,
                severity="critical",
                confidence="confirmed",
                evidence=f"Forged unsigned token accepted -> HTTP {resp.status_code}",
                description=(
                    "The server accepted a JWT with `alg: none` and no signature, "
                    "meaning any client can forge a token with arbitrary claims "
                    "(including elevated roles) without knowing any secret."
                ),
                remediation="Explicitly whitelist accepted algorithms server-side (e.g. only HS256/RS256) and reject 'none' unconditionally.",
                cwe="CWE-347",
            )
        return None

    async def _check_expired_reuse(self, token: str, header: dict, payload: dict) -> Finding | None:
        if "exp" not in payload:
            return None
        expired_payload = dict(payload)
        expired_payload["exp"] = int(time.time()) - 3600
        try:
            forged = jwt.encode(
                expired_payload, key="stelarstrike-probe-key", algorithm=header.get("alg", "HS256")
            )
        except Exception:
            return None
        resp = await self.get(self.target_url, headers={"Authorization": f"Bearer {forged}"})
        if resp.status_code == 200:
            return self.finding(
                title="Server may not be validating JWT expiry",
                url=self.target_url,
                severity="medium",
                confidence="low",
                evidence=f"Re-signed token with 'exp' one hour in the past -> HTTP {resp.status_code}",
                description=(
                    "A token with an expiry timestamp in the past (re-signed with a "
                    "probe key) was accepted. This specific probe uses a different "
                    "signing key, so verify manually with a genuinely expired, "
                    "correctly-signed token before treating this as confirmed."
                ),
                remediation="Ensure the JWT library's expiry check ('exp' claim) is enabled and enforced on every request.",
                cwe="CWE-613",
            )
        return None
