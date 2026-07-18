"""
Plugin registry.

To add a new vulnerability class:
  1. Create stelarstrike/plugins/<your_plugin>.py subclassing VulnerabilityPlugin.
  2. Import it below and add it to PLUGIN_REGISTRY with a unique id
     (this id must match a section under `plugins:` in config.yaml).

Nothing else in the codebase needs to change — the orchestrator and
CLI both discover plugins purely through this dict.
"""

from assets.plugins.csrf import CSRFPlugin
from assets.plugins.file_upload import FileUploadPlugin
from assets.plugins.idor import IDORPlugin
from assets.plugins.jwt_vuln import JWTPlugin
from assets.plugins.nosqli import NoSQLiPlugin
from assets.plugins.sqli import SQLiPlugin
from assets.plugins.ssrf import SSRFPlugin
from assets.plugins.xss import XSSPlugin

PLUGIN_REGISTRY = {
    "sqli": SQLiPlugin,
    "nosqli": NoSQLiPlugin,
    "xss": XSSPlugin,
    "ssrf": SSRFPlugin,
    "csrf": CSRFPlugin,
    "file_upload": FileUploadPlugin,
    "idor": IDORPlugin,
    "jwt": JWTPlugin,
}
