"""
Insecure File Upload plugin.

Detection strategy:
  1. Locate <form> elements containing a file input.
  2. For each, upload a series of harmless, non-executable probe files
     whose *extensions* match commonly-dangerous types (.php, .jsp, ...)
     but whose *content* is inert plain text — this checks whether the
     extension/MIME allowlist rejects them, without ever uploading
     working executable code.
  3. If the upload is accepted (2xx) and the app discloses a reachable
     URL for the uploaded file, the plugin fetches that URL and confirms
     the inert marker is served back verbatim — proving the dangerous
     extension was accepted and is web-accessible.

This never uploads a working webshell. It only proves "this extension
was accepted and stored somewhere reachable," which is exactly the
precondition an attacker needs — the report flags it as high severity
without requiring an actual exploit.
"""

from __future__ import annotations

import re
import uuid

from assets.core.report import Finding
from assets.plugins.base import VulnerabilityPlugin
from assets.utils.http_client import extract_forms

_URL_HINT_PATTERN = re.compile(r"""(https?://[^\s"'<>]+|/[a-zA-Z0-9_\-./]+\.(?:php|jsp|asp|svg|txt))""")


class FileUploadPlugin(VulnerabilityPlugin):
    id = "file_upload"
    name = "Insecure File Upload"
    default_severity = "high"

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.ctx.allow_active_payloads:
            findings.append(
                self.finding(
                    title="File upload check skipped (active payloads disabled)",
                    url=self.target_url,
                    severity="informational",
                    confidence="low",
                    description=(
                        "A file upload form may be present, but active upload probes "
                        "are disabled. Set engagement.allow_active_payloads: true to run them."
                    ),
                )
            )
            return findings

        resp = await self.get(self.target_url)
        forms = extract_forms(resp.text)
        upload_forms = [
            f for f in forms
            if any(i["type"] == "file" for i in f["inputs"]) and f["method"] == "post"
        ]
        if not upload_forms:
            return findings

        extensions = self.options.get(
            "test_extensions", [".php", ".php5", ".phtml", ".svg", ".jsp", ".asp"]
        )

        for form in upload_forms:
            action_url = form["action"] or self.target_url
            action_url = action_url if action_url.startswith("http") else self.target_url
            file_field = next(i["name"] for i in form["inputs"] if i["type"] == "file")

            for ext in extensions:
                marker = f"STELARSTRIKE-{uuid.uuid4().hex[:10]}"
                filename = f"stelarstrike-probe{ext}"
                inert_content = f"<!-- {marker} : inert probe, not executable -->".encode()

                files = {file_field: (filename, inert_content, "application/octet-stream")}
                data = {
                    i["name"]: i.get("value", "test")
                    for i in form["inputs"]
                    if i["name"] != file_field and i["type"] != "file"
                }

                try:
                    upload_resp = await self.post(action_url, data=data, files=files)
                except Exception:
                    continue

                if upload_resp.status_code >= 400:
                    continue

                hosted_url = self._extract_hosted_url(upload_resp.text, filename)
                if hosted_url:
                    verify_resp = await self.get(hosted_url)
                    if marker in verify_resp.text:
                        findings.append(
                            self.finding(
                                title=f"Insecure File Upload: '{ext}' accepted and web-reachable",
                                url=action_url,
                                parameter=file_field,
                                severity="critical",
                                confidence="confirmed",
                                evidence=f"Uploaded '{filename}', retrieved marker back at {hosted_url}",
                                description=(
                                    f"The upload form accepted a file with extension "
                                    f"'{ext}' and the file is reachable and served from "
                                    f"'{hosted_url}'. If the server executes this "
                                    f"extension, this is a remote code execution path."
                                ),
                                remediation=(
                                    "Validate uploads by content (magic bytes), not extension. "
                                    "Store uploads outside the webroot or in object storage with "
                                    "no execute permission, and serve them through a handler that "
                                    "forces safe Content-Type/Content-Disposition."
                                ),
                                cwe="CWE-434",
                            )
                        )
                        continue

                findings.append(
                    self.finding(
                        title=f"File Upload: '{ext}' extension accepted by server (reachability unconfirmed)",
                        url=action_url,
                        parameter=file_field,
                        severity="medium",
                        confidence="low",
                        evidence=f"Uploaded '{filename}' -> HTTP {upload_resp.status_code}, no hosted URL found in response.",
                        description=(
                            f"The server accepted a file with a commonly-dangerous "
                            f"extension ('{ext}') without an apparent extension check. "
                            f"Manual review is needed to determine where the file is "
                            f"stored and whether it is web-reachable/executable."
                        ),
                        remediation="Validate uploads by content type/magic bytes and maintain an extension allowlist.",
                        cwe="CWE-434",
                    )
                )

        return findings

    @staticmethod
    def _extract_hosted_url(body: str, filename: str) -> str | None:
        match = _URL_HINT_PATTERN.search(body)
        if match and filename.split(".")[0] in match.group(0):
            return match.group(0)
        return None
