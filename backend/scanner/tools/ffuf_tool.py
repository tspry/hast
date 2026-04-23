"""ffuf – directory/file brute-force across all major stacks."""
from __future__ import annotations

import json
import os
import tempfile
from typing import AsyncIterator

from backend.config import get_config, get_ffuf_wordlist
from backend.scanner.tools.base import Finding, SimpleToolRunner, ToolEvent

# ---------------------------------------------------------------------------
# PRIORITY_PATHS — probed on every scan regardless of profile.
# Covers: .NET, PHP (Laravel/WP/Symfony/Drupal/Joomla/CodeIgniter),
#         React/Vue/Angular/Next.js/Nuxt, Node.js/Express/NestJS,
#         Python (Django/Flask/FastAPI), Ruby on Rails, Java/Spring Boot,
#         Go, and generic DevOps/infrastructure files.
# ---------------------------------------------------------------------------
PRIORITY_PATHS = [

    # ── Environment files (all stacks) ───────────────────────────────────────
    ".env",
    ".env.local",
    ".env.development",
    ".env.dev",
    ".env.staging",
    ".env.production",
    ".env.prod",
    ".env.test",
    ".env.backup",
    ".env.example",       # often contains real values despite the name
    ".env.sample",
    ".env.bak",
    ".env.old",
    ".env.save",
    "env",
    "env.json",
    "env.js",             # runtime env injection (React/Angular)
    "env-config.js",      # common SPA runtime config pattern
    "environment.js",
    "environment.json",
    "environment.prod.js",
    "environment.production.js",

    # ── .NET / ASP.NET Core ───────────────────────────────────────────────────
    "appsettings.json",
    "appsettings.Development.json",
    "appsettings.Production.json",
    "appsettings.Staging.json",
    "appsettings.Local.json",
    "appsettings.secrets.json",
    "appsettings.override.json",
    "appsettings.Test.json",
    "runtime.json",
    "runtimeconfig.json",
    "runtimeconfig.template.json",
    "launchSettings.json",
    "Properties/launchSettings.json",
    "web.config",
    "web.Release.config",
    "web.Debug.config",
    "connectionstrings.json",
    "ConnectionStrings.json",
    "secrets.json",
    "usersecrets.json",
    "global.json",
    "nuget.config",
    "NuGet.Config",
    "bundleconfig.json",
    "compilerconfig.json",
    "elmah.axd",
    "trace.axd",
    "_debug",
    "_profiler",

    # ── PHP – Laravel ──────────────────────────────────────────────────────────
    "artisan",
    "bootstrap/cache/config.php",  # cached config — contains ALL secrets
    "bootstrap/cache/services.php",
    "bootstrap/cache/packages.php",
    "config/app.php",
    "config/database.php",
    "config/mail.php",
    "config/services.php",
    "config/filesystems.php",
    "storage/logs/laravel.log",
    "storage/logs/lumen.log",
    "storage/framework/sessions",
    ".phpunit.result.cache",
    "phpunit.xml",

    # ── PHP – WordPress ────────────────────────────────────────────────────────
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php.old",
    "wp-config.php.orig",
    "wp-config.php.save",
    "wp-config-sample.php",
    "wp-login.php",
    "xmlrpc.php",              # DDoS amplification vector
    "wp-content/debug.log",
    "wp-content/uploads/.htaccess",
    ".wp-config.php.swp",

    # ── PHP – Symfony ──────────────────────────────────────────────────────────
    "app/config/parameters.yml",
    "app/config/parameters.yaml",
    "config/packages/doctrine.yaml",
    "config/packages/security.yaml",
    ".env.local.php",

    # ── PHP – Drupal ───────────────────────────────────────────────────────────
    "sites/default/settings.php",
    "sites/default/settings.local.php",
    "sites/default/services.yml",

    # ── PHP – Joomla ───────────────────────────────────────────────────────────
    "configuration.php",
    "configuration.php.bak",

    # ── PHP – CodeIgniter ─────────────────────────────────────────────────────
    "application/config/database.php",
    "application/config/config.php",

    # ── PHP – generic ─────────────────────────────────────────────────────────
    "phpinfo.php",
    "info.php",
    "php.ini",
    "php-errors.log",
    "php_errors.log",
    "config.php",
    "database.php",
    "db.php",
    "db_config.php",
    "connect.php",
    "connection.php",
    ".htaccess",
    ".htpasswd",
    "composer.json",
    "composer.lock",

    # ── Node.js / Express / NestJS ────────────────────────────────────────────
    "package.json",
    "package-lock.json",
    "yarn.lock",
    ".npmrc",               # may contain npm auth tokens
    ".yarnrc",
    ".yarnrc.yml",
    ".nvmrc",
    "nest-cli.json",
    "config/default.json",  # node-config
    "config/default.yaml",
    "config/default.yml",
    "config/production.json",
    "config/production.yaml",
    "config/local.json",
    "config/local.yaml",
    "config/development.json",
    "config/secrets.json",
    "config/database.json",
    "server.js",
    "app.js",
    "index.js",

    # ── React / Vue / Angular / Next.js / Nuxt (SPA) ─────────────────────────
    "runtime-config.js",
    "runtime-config.json",
    "app-config.js",
    "app-config.json",
    "app.config.js",
    "app.config.json",
    "__ENV.js",             # Angular runtime env pattern
    "config.js",
    "settings.js",
    "constants.js",
    "next.config.js",
    "next.config.ts",
    "nuxt.config.js",
    "nuxt.config.ts",
    "vue.config.js",
    "angular.json",
    "vite.config.js",
    "vite.config.ts",
    ".vite/deps/",
    # Source maps — expose full source code
    "static/js/main.chunk.js.map",
    "static/js/bundle.js.map",
    "js/app.js.map",
    "js/main.js.map",

    # ── Python – Django ────────────────────────────────────────────────────────
    "manage.py",
    "settings.py",
    "local_settings.py",
    "config/settings/base.py",
    "config/settings/local.py",
    "config/settings/production.py",
    "config/settings.py",
    "wsgi.py",
    "asgi.py",

    # ── Python – Flask ─────────────────────────────────────────────────────────
    "instance/config.py",
    "instance/settings.py",
    ".flaskenv",
    "config.cfg",
    "application.cfg",

    # ── Python – generic ──────────────────────────────────────────────────────
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "poetry.lock",
    "celeryconfig.py",
    "gunicorn.conf.py",

    # ── Ruby on Rails ─────────────────────────────────────────────────────────
    "config/database.yml",
    "config/secrets.yml",
    "config/credentials.yml.enc",
    "config/master.key",        # CRITICAL — decrypts all Rails credentials
    "config/application.yml",   # figaro gem
    "config/storage.yml",
    "config/cable.yml",
    "config/environments/production.rb",
    "config/environments/development.rb",
    "Gemfile",
    "Gemfile.lock",
    ".ruby-version",

    # ── Java / Spring Boot ────────────────────────────────────────────────────
    "application.properties",
    "application.yml",
    "application.yaml",
    "application-production.properties",
    "application-production.yml",
    "application-prod.properties",
    "application-prod.yml",
    "application-dev.properties",
    "application-staging.yml",
    "bootstrap.properties",
    "bootstrap.yml",
    "log4j.properties",
    "log4j2.xml",
    # Spring Boot Actuator
    "actuator",
    "actuator/health",
    "actuator/env",
    "actuator/mappings",
    "actuator/beans",
    "actuator/configprops",
    "actuator/loggers",
    "actuator/heapdump",
    "actuator/threaddump",
    "actuator/metrics",
    "actuator/info",

    # ── Go ────────────────────────────────────────────────────────────────────
    "config.toml",
    "config.hcl",
    "go.sum",

    # ── Generic config / secrets ──────────────────────────────────────────────
    "config.json",
    "config.yml",
    "config.yaml",
    "config.xml",
    "config.ini",
    "config.cfg",
    "configuration.json",
    "configuration.xml",
    "settings.json",
    "settings.xml",
    "credentials.json",
    "credentials.yml",
    "secrets.yml",
    "keystore.json",
    "keystore.jks",
    "truststore.jks",
    "serviceAccountKey.json",
    "service-account.json",
    "firebase-adminsdk.json",
    ".vault-token",
    "vault.json",

    # ── Infrastructure / DevOps ───────────────────────────────────────────────
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.override.yml",
    "docker-compose.prod.yml",
    "docker-compose.production.yml",
    "docker-compose.dev.yml",
    ".dockerenv",
    "Dockerfile",
    ".dockerfile",
    "k8s.yml",
    "k8s.yaml",
    "kubernetes.yml",
    "kubernetes.yaml",
    "helm/values.yaml",
    "chart/values.yaml",
    "values.yaml",
    "deploy.yml",
    "deploy.yaml",
    ".travis.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    ".github/workflows/deploy.yml",
    ".github/workflows/ci.yml",
    "ansible.cfg",
    "inventory",
    "inventory.yml",
    "hosts",
    "terraform.tfvars",
    "terraform.tfvars.json",
    "terraform.tfstate",
    "terraform.tfstate.backup",

    # ── Git ───────────────────────────────────────────────────────────────────
    ".git/config",
    ".git/HEAD",
    ".git/COMMIT_EDITMSG",
    ".git/description",
    ".gitignore",
    ".gitconfig",
    ".gitmodules",
    ".gitattributes",

    # ── Logs ──────────────────────────────────────────────────────────────────
    "error.log",
    "errors.log",
    "debug.log",
    "app.log",
    "application.log",
    "access.log",
    "server.log",
    "logs/error.log",
    "logs/debug.log",
    "logs/app.log",
    "logs/access.log",
    "log/error.log",
    "log/app.log",
    "tmp/debug.log",

    # ── Backups & dumps ───────────────────────────────────────────────────────
    "backup.sql",
    "dump.sql",
    "db.sql",
    "database.sql",
    "data.sql",
    "users.sql",
    "backup.zip",
    "backup.tar.gz",
    "backup.tar",
    "backup.bak",
    "site.zip",
    "site.tar.gz",
    "www.zip",
    "www.tar.gz",
    "htdocs.zip",
    "public_html.zip",
    "app.zip",

    # ── API docs ──────────────────────────────────────────────────────────────
    "swagger.json",
    "swagger.yaml",
    "swagger.yml",
    "openapi.json",
    "openapi.yaml",
    "openapi.yml",
    "api-docs",
    "api-docs/swagger.json",
    "v1/api-docs",
    "v2/api-docs",
    "v3/api-docs",
    "api/swagger.json",
    "api/openapi.json",
    "graphql",
    "graphiql",
    "__graphql",
    "playground",         # GraphQL playground

    # ── SSH / certs ───────────────────────────────────────────────────────────
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/id_ecdsa",
    ".ssh/authorized_keys",
    "id_rsa",
    "private.key",
    "private.pem",
    "server.key",
    "server.pem",
    "ssl.key",
    "cert.pem",
    "certificate.pem",

    # ── Cloud provider credentials ────────────────────────────────────────────
    ".aws/credentials",
    ".aws/config",
    "aws-credentials.json",
    "gcloud/credentials.json",
    ".config/gcloud/credentials.db",

    # ── Misc ──────────────────────────────────────────────────────────────────
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "server-status",
    "server-info",
    ".DS_Store",
    ".bash_history",
    ".bash_profile",
    ".bashrc",
    "web.xml",             # Java EE
    "faces-config.xml",    # JSF
    "struts.xml",          # Struts
    "hibernate.cfg.xml",   # Hibernate
    "persistence.xml",     # JPA
    "pom.xml",             # Maven
    "build.gradle",        # Gradle
]

# ---------------------------------------------------------------------------
# REMEDIATION lookup — partial key match against path_lower
# ---------------------------------------------------------------------------
REMEDIATION_FOR = {
    # .NET
    ".env":               "Remove .env from web root immediately. Rotate all exposed credentials.",
    "appsettings":        "Remove appsettings.json from web root. Store secrets in environment variables or a secrets manager (Azure Key Vault, AWS Secrets Manager, Vault).",
    "runtime.json":       "Remove runtime.json from web root. May expose .NET runtime configuration.",
    "launchsettings":     "Remove launchSettings.json — it contains env vars and port bindings for development only.",
    "connectionstring":   "Remove connectionstrings.json from web root immediately. It contains database credentials.",
    "web.config":         "Restrict web.config via IIS rules. Move secrets to environment variables or Key Vault.",
    # PHP
    "wp-config":          "Block wp-config.php via .htaccess or nginx `deny all`. It contains DB host, user, and password.",
    "configuration.php":  "Block configuration.php — it contains Joomla database credentials.",
    "sites/default/settings": "Block Drupal settings.php — it contains database credentials.",
    "bootstrap/cache":    "Block Laravel bootstrap/cache/ — cached config contains all application secrets.",
    "xmlrpc.php":         "Disable xmlrpc.php (add `deny all` in nginx/Apache). Used for DDoS amplification and brute-force.",
    "artisan":            "Block access to artisan. It should never be web-accessible.",
    "composer":           "Block composer.json/lock — reveals exact dependency versions for CVE targeting.",
    ".htpasswd":          "Remove .htpasswd from web root immediately. Contains hashed credentials.",
    ".htaccess":          "Review .htaccess contents. It may expose security rules or redirect logic.",
    # Node / JS
    ".npmrc":             "Remove .npmrc from web root immediately. May contain npm auth tokens with registry access.",
    "package.json":       "Block package.json — reveals exact dependency versions for CVE targeting.",
    "yarn.lock":          "Block yarn.lock — reveals exact dependency versions for CVE targeting.",
    "next.config":        "Block next.config.js — may expose environment variables and internal routing.",
    "runtime-config":     "Block runtime-config.js/json — contains runtime environment variables for the SPA.",
    "env-config":         "Block env-config.js — contains runtime environment variables injected into the SPA.",
    "__env":              "Block __ENV.js — contains runtime environment variables exposed to the Angular app.",
    ".js.map":            "Block .js.map source map files in production. They expose full original source code.",
    "constants.js":       "Review constants.js — may contain API keys, endpoints, or feature flags.",
    # Python
    "settings.py":        "Block settings.py — Django settings file contains SECRET_KEY and database credentials.",
    "local_settings.py":  "Block local_settings.py — contains environment-specific secrets.",
    "instance/config":    "Block Flask instance/config.py — contains SECRET_KEY and database URI.",
    ".flaskenv":          "Remove .flaskenv from web root — contains Flask environment variables.",
    "manage.py":          "Block manage.py — should never be web-accessible.",
    "requirements.txt":   "Block requirements.txt — reveals dependency versions for CVE targeting.",
    # Ruby on Rails
    "config/master.key":  "CRITICAL: Block config/master.key immediately. This key decrypts all Rails credentials.",
    "config/secrets.yml": "Block config/secrets.yml — contains Rails secret_key_base and other secrets.",
    "config/database.yml":"Block config/database.yml — contains database host, username, and password.",
    "config/application.yml": "Block config/application.yml (figaro) — contains app-level secrets.",
    "gemfile":            "Block Gemfile — reveals exact gem versions for CVE targeting.",
    # Java / Spring
    "application.properties": "Block application.properties — may contain DB credentials, API keys, and cloud tokens.",
    "application.yml":    "Block application.yml — may contain DB credentials, API keys, and cloud tokens.",
    "bootstrap.yml":      "Block bootstrap.yml — Spring Cloud config, may contain config server credentials.",
    "log4j":              "Review log4j config exposure. Log4Shell (CVE-2021-44228) affects log4j 2.x.",
    "actuator/env":       "CRITICAL: Restrict /actuator/env — exposes all env vars including secrets in plaintext.",
    "actuator/heapdump":  "CRITICAL: Restrict /actuator/heapdump — heap dumps contain secrets extracted from memory.",
    "actuator/configprops":"Restrict /actuator/configprops — exposes all Spring configuration properties.",
    "actuator":           "Restrict Spring Boot Actuator endpoints to trusted IPs via Spring Security or firewall.",
    "pom.xml":            "Block pom.xml — reveals exact dependency versions for CVE targeting.",
    # Go
    "config.toml":        "Block config.toml — may contain database credentials and API keys.",
    # Git
    ".git":               "Block .git/ access (nginx: `deny all`; Apache: `Require all denied`). Exposed git history leaks full source code.",
    # Infra / DevOps
    "docker-compose":     "Remove docker-compose files from web root. They expose service names, ports, env vars, and credentials.",
    "terraform.tfstate":  "CRITICAL: Remove Terraform state files — tfstate contains plaintext infrastructure secrets.",
    "terraform.tfvars":   "CRITICAL: Remove terraform.tfvars — contains plaintext infrastructure credentials.",
    "values.yaml":        "Block Helm values.yaml — may contain image pull secrets and app credentials.",
    "jenkinsfile":        "Remove Jenkinsfile — may reveal CI/CD structure and credential variable names.",
    "serviceaccount":     "Remove GCP service account key immediately. Rotate the key in GCP IAM.",
    "firebase":           "Remove Firebase admin SDK key immediately. Rotate in Firebase Console.",
    ".vault-token":       "Remove Vault token from web root. Rotate the token in Vault immediately.",
    # Cloud
    ".aws/credentials":   "CRITICAL: Remove AWS credentials file immediately. Rotate keys in IAM.",
    "aws-credentials":    "CRITICAL: Remove AWS credentials immediately. Rotate keys in IAM.",
    # Backups / dumps
    "backup":             "Remove backup/dump files from web root. May contain full source code, DB dumps, or credentials.",
    "dump.sql":           "Remove SQL dump from web root immediately. Contains full database contents.",
    ".sql":               "Remove SQL files from web root. May contain full database contents including credentials.",
    # Logs
    ".log":               "Block log files — logs contain stack traces, file paths, user data, and sometimes credentials.",
    "laravel.log":        "Block Laravel log files — contain stack traces with file paths and sensitive request data.",
    # API docs
    "swagger":            "Restrict Swagger/OpenAPI docs to authenticated users in production.",
    "openapi":            "Restrict OpenAPI docs to authenticated users in production.",
    "graphql":            "Disable GraphQL introspection in production. It exposes the full schema.",
    "playground":         "Disable GraphQL playground in production.",
    # Misc
    "phpinfo":            "Remove phpinfo() pages — expose server config, PHP version, and all loaded modules.",
    "xmlrpc":             "Disable xmlrpc.php — used for DDoS amplification and credential brute-force.",
    ".ssh":               "Remove SSH keys from web root immediately. Rotate any exposed private keys.",
    "private.key":        "Remove private key from web root immediately. Reissue the certificate.",
    "id_rsa":             "Remove SSH private key from web root immediately. Rotate the key.",
    "server.key":         "Remove TLS private key from web root immediately. Reissue the certificate.",
    ".htpasswd":          "Remove .htpasswd from web root immediately. Contains hashed credentials.",
    ".ds_store":          "Remove .DS_Store files — they leak directory structure to attackers.",
    ".bash_history":      "Remove .bash_history from web root — contains command history including credentials.",
}

# Severity tiers — checked in order, first match wins
_CRITICAL = [
    ".env", "appsettings", "web.config", "connectionstring", "secrets.json",
    "credentials", "serviceaccount", "firebase", "terraform.tfstate",
    "terraform.tfvars", ".ssh", "id_rsa", "id_ed25519", "private.key",
    "server.key", ".htpasswd", "runtime.json", "launchsettings",
    ".vault-token", "config/master.key", "bootstrap/cache/config",
    "sites/default/settings", "wp-config", "configuration.php",
    "actuator/env", "actuator/heapdump", "actuator/configprops",
    "application.properties", "application.yml", "bootstrap.yml",
    ".aws/credentials", "aws-credentials", ".npmrc",
    "config/secrets.yml", "config/database.yml", "config/application.yml",
    "config/master.key", "database.php", "db.php", "connect.php",
    "instance/config", "local_settings.py", "__env.js",
    "runtime-config", "env-config",
]
_HIGH = [
    "backup", "dump.sql", "db.sql", ".sql", "docker-compose", "dockerfile",
    "config.json", "config.yml", "config.yaml", "config.toml",
    "settings.json", "parameters.yml", "package.json", "composer.json",
    "actuator", ".git/head", ".git/config", "values.yaml",
    "error.log", "debug.log", ".log", "laravel.log",
    "app/config/parameters", "config/database", "settings.py",
    ".flaskenv", "manage.py", "artisan", "gemfile",
    "pom.xml", "build.gradle",
]
_MEDIUM = [
    "phpinfo", "info.php", "swagger", "openapi", "api-docs", "graphql",
    "playground", "server-status", "elmah", "_debug", "_profiler",
    "xmlrpc", "robots.txt", "sitemap.xml", "requirements.txt",
    "package-lock.json", "yarn.lock", ".js.map", "next.config",
    "nuxt.config", "vue.config", "angular.json", "composer.lock",
    "gemfile.lock", "poetry.lock", "pipfile.lock",
]


class FfufTool(SimpleToolRunner):
    name = "ffuf"
    binary = "ffuf"

    async def run(
        self,
        target: str,
        use_full_wordlist: bool = False,
    ) -> AsyncIterator[ToolEvent | Finding]:
        if not self.available:
            yield self._unavailable_event()
            return

        cfg = get_config()
        rate_ms = cfg.get("rate_limit_ms", 150)
        rate_rps = max(1, 1000 // max(rate_ms, 1))

        base = target.rstrip("/")
        url_template = f"{base}/FUZZ"

        wordlist_path = None
        if use_full_wordlist:
            wordlist_path = get_ffuf_wordlist()
            if not wordlist_path:
                yield ToolEvent(
                    stream="warning",
                    data="[ffuf] raft-medium-files.txt not found — using priority paths only",
                    tool=self.name,
                )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            for path in PRIORITY_PATHS:
                tf.write(path + "\n")
            priority_file = tf.name

        out_file = tempfile.mktemp(suffix=".json")

        try:
            for wl, label in [(priority_file, "priority"), (wordlist_path, "full")]:
                if not wl:
                    continue
                yield ToolEvent(
                    stream="info",
                    data=f"[ffuf] {label} scan — {len(PRIORITY_PATHS) if label == 'priority' else 'full wordlist'} paths against {base}",
                    tool=self.name,
                )
                args = [
                    "-u", url_template,
                    "-w", wl,
                    "-mc", "200,201,301,302,307,308",
                    "-fc", "403,404,429",
                    "-o", out_file,
                    "-of", "json",
                    "-t", "20",
                    "-rate", str(rate_rps),
                    "-timeout", "10",
                    "-silent",
                ]
                async for ev in self.run_raw(args, timeout=600):
                    yield ev

                for f in _parse_ffuf_output(out_file, target):
                    yield f

                try:
                    os.unlink(out_file)
                except Exception:
                    pass
        finally:
            try:
                os.unlink(priority_file)
            except Exception:
                pass


def _parse_ffuf_output(output_file: str, target: str) -> list[Finding]:
    findings = []
    try:
        with open(output_file) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return findings

    for r in data.get("results", []):
        url    = r.get("url", "")
        status = r.get("status", 0)
        length = r.get("length", 0)
        path   = r.get("input", {}).get("FUZZ", "")
        path_lower = path.lower()

        # Remediation: first partial key match wins
        remediation = "Review and restrict access to this file."
        for keyword, remed in REMEDIATION_FOR.items():
            if keyword in path_lower:
                remediation = remed
                break

        # Severity tier
        if any(k in path_lower for k in _CRITICAL):
            severity = "critical" if status == 200 else "high"
        elif any(k in path_lower for k in _HIGH):
            severity = "high" if status == 200 else "medium"
        elif any(k in path_lower for k in _MEDIUM):
            severity = "medium"
        else:
            severity = "low"

        findings.append(Finding(
            tool="ffuf",
            severity=severity,
            name=f"Exposed File: {path}",
            url=url,
            evidence=f"HTTP {status} — {length} bytes — path: {path}",
            remediation=remediation,
            raw=r,
        ))

    return findings
