from __future__ import annotations

from stelarstrike.plugins.base import VulnerabilityPlugin


class SQLInjectionPlugin(VulnerabilityPlugin):
    id = "sqli"
    name = "SQL Injection"
    default_severity = "high"


class NoSQLInjectionPlugin(VulnerabilityPlugin):
    id = "nosqli"
    name = "NoSQL Injection"
    default_severity = "high"


class XSSPlugin(VulnerabilityPlugin):
    id = "xss"
    name = "Cross-Site Scripting"
    default_severity = "medium"


class SSRFPlugin(VulnerabilityPlugin):
    id = "ssrf"
    name = "Server-Side Request Forgery"
    default_severity = "high"


class CSRFPlugin(VulnerabilityPlugin):
    id = "csrf"
    name = "Cross-Site Request Forgery"
    default_severity = "medium"


class FileUploadPlugin(VulnerabilityPlugin):
    id = "file_upload"
    name = "Insecure File Upload"
    default_severity = "high"


class IDORPlugin(VulnerabilityPlugin):
    id = "idor"
    name = "Insecure Direct Object Reference"
    default_severity = "high"


class JWTPlugin(VulnerabilityPlugin):
    id = "jwt"
    name = "JSON Web Token"
    default_severity = "high"


PLUGIN_REGISTRY: dict[str, type[VulnerabilityPlugin]] = {
    plugin.id: plugin
    for plugin in (
        SQLInjectionPlugin,
        NoSQLInjectionPlugin,
        XSSPlugin,
        SSRFPlugin,
        CSRFPlugin,
        FileUploadPlugin,
        IDORPlugin,
        JWTPlugin,
    )
}
