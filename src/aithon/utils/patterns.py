"""Regex patterns for secret detection."""

SECRET_PATTERNS: dict[str, str] = {
    # LLM provider keys
    "OpenAI API Key": r"sk-(?!ant-|or-|cp-)[a-zA-Z0-9]{32,}",
    "Anthropic API Key": r"sk-ant-[a-zA-Z0-9\-]{20,}",
    "Anthropic Setup Token": r"stp-[a-zA-Z0-9\-]{20,}",
    "DeepSeek API Key": r"sk-(?!ant-|or-|cp-)[a-f0-9]{48,}",
    "OpenRouter Key": r"sk-or-v1-[a-f0-9]{64}",
    "MiniMax Key": r"sk-cp-[A-Za-z0-9]{20,}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "NVIDIA API Key": r"nvapi-[A-Za-z0-9\-_]{20,}",
    "Copilot Token": r"ghu_[A-Za-z0-9]{36,}",
    # Cloud provider keys
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
    # Code / CI tokens
    "GitHub Token": r"gh[ps]_[A-Za-z0-9_]{36,}",
    "GitHub Fine-Grained Token": r"github_pat_[A-Za-z0-9_]{22,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    # Crypto / keys
    "Private Key Block": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    # Messaging
    "Telegram Bot Token": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    # Generic catch-all (low confidence, still useful)
    "Generic High-Entropy Secret": (
        r"(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?"
        r"[A-Za-z0-9+/=]{20,}['\"]?"
    ),
}
