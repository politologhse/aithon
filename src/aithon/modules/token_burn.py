"""Token burn and cost optimization detection."""
from __future__ import annotations

import json
import re
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


# Models known to be expensive in primary slot
EXPENSIVE_MODELS = {
    "claude-opus-4-6", "claude-opus-4-5", "claude-opus-4",
    "claude-sonnet-4-5",
    "gpt-5", "gpt-5-pro",
    "o3", "o3-pro",
    "gemini-3-pro", "gemini-2.5-pro",
}

# Cheap models suitable for primary/default
CHEAP_MODELS = {
    "claude-haiku-4-5", "claude-haiku-4",
    "gpt-5-mini", "gpt-5-nano", "gpt-4o-mini",
    "gemini-3-flash", "gemini-2.5-flash", "gemini-2.5-flash-lite",
    "qwen-flash", "qwen3-4b",
    "kimi-k2.5", "k2p5",
}


class TokenBurnModule(BaseModule):

    @property
    def name(self) -> str:
        return "token_burn"

    @property
    def description(self) -> str:
        return "Detects costly model configurations and missing optimization settings"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        config_files = self.agent.get_config_files(self.config.target)

        for cfg_path in config_files:
            if cfg_path.name != "openclaw.json":
                continue
            try:
                content = cfg_path.read_text(errors="ignore")
                lines = [ln for ln in content.splitlines() if not ln.lstrip().startswith("//")]
                clean = re.sub(r",\s*([}\]])", r"\1", "\n".join(lines))
                data = json.loads(clean)
            except (json.JSONDecodeError, PermissionError, OSError):
                continue
            if not isinstance(data, dict):
                continue

            findings.extend(self._check_expensive_primary(cfg_path, data))
            findings.extend(self._check_no_fallbacks(cfg_path, data))
            findings.extend(self._check_no_context_overflow(cfg_path, data))
            findings.extend(self._check_no_cache_ttl(cfg_path, data))
            findings.extend(self._check_expensive_embeddings(cfg_path, data))
            findings.extend(self._check_cron_models(cfg_path, data))

        return findings

    def _extract_model_id(self, model_ref: str) -> str:
        """Extract model ID from provider/model format."""
        if "/" in model_ref:
            return model_ref.split("/", 1)[1]
        return model_ref

    def _is_expensive(self, model_ref: str) -> bool:
        model_id = self._extract_model_id(model_ref)
        return any(exp in model_id for exp in EXPENSIVE_MODELS)

    def _check_expensive_primary(self, path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        agents = data.get("agents", data.get("agent", {}))
        if not isinstance(agents, dict):
            return findings

        defaults = agents.get("defaults", agents)
        if not isinstance(defaults, dict):
            return findings

        model_cfg = defaults.get("model", {})
        if isinstance(model_cfg, str):
            primary = model_cfg
        elif isinstance(model_cfg, dict):
            primary = model_cfg.get("primary", "")
        else:
            return findings

        if primary and self._is_expensive(primary):
            findings.append(Finding(
                id=f"BURN-{len(findings) + 1:03d}",
                title=f"Expensive model as default: {primary}",
                severity=Severity.MEDIUM,
                module=self.name,
                description=(
                    f"Primary model is '{primary}' — an expensive model. "
                    "Every routine message burns premium tokens. Use a cheaper model "
                    "as default and keep expensive models in fallbacks or per-agent configs."
                ),
                file_path=str(path),
                evidence=f"primary: {primary}",
                remediation=(
                    "Set a cheaper model as primary (haiku, gpt-5-mini, gemini-flash) "
                    "and move expensive models to fallbacks."
                ),
            ))
        return findings

    def _check_no_fallbacks(self, path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        agents = data.get("agents", data.get("agent", {}))
        if not isinstance(agents, dict):
            return findings

        defaults = agents.get("defaults", agents)
        if not isinstance(defaults, dict):
            return findings

        model_cfg = defaults.get("model", {})
        if isinstance(model_cfg, dict):
            fallbacks = model_cfg.get("fallbacks", [])
            if not fallbacks:
                findings.append(Finding(
                    id=f"BURN-{len(findings) + 1:03d}",
                    title="No model fallbacks configured",
                    severity=Severity.MEDIUM,
                    module=self.name,
                    description=(
                        "No fallback models defined. If the primary model hits rate limits "
                        "or goes down, the agent stops working entirely. Fallbacks also "
                        "enable cost optimization by cascading to cheaper models."
                    ),
                    file_path=str(path),
                    remediation=(
                        "Add fallbacks: agents.defaults.model.fallbacks: "
                        '["openai/gpt-5-mini", "openrouter/google/gemini-3-flash"]'
                    ),
                ))
        return findings

    def _check_no_context_overflow(self, path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        agents = data.get("agents", data.get("agent", {}))
        if not isinstance(agents, dict):
            return findings

        defaults = agents.get("defaults", agents)
        if not isinstance(defaults, dict):
            return findings

        context = defaults.get("context", defaults.get("contextOverflow", {}))
        memory_flush = defaults.get("memoryFlush", defaults.get("memory_flush", {}))

        has_threshold = False
        if isinstance(context, dict):
            has_threshold = bool(context.get("softThresholdTokens") or context.get("maxTokens"))
        if isinstance(memory_flush, dict) and memory_flush.get("enabled"):
            has_threshold = True

        if not has_threshold:
            findings.append(Finding(
                id=f"BURN-{len(findings) + 1:03d}",
                title="No context overflow / memory flush configured",
                severity=Severity.MEDIUM,
                module=self.name,
                description=(
                    "No softThresholdTokens or memoryFlush configured. "
                    "Long conversations will hit token limits and the agent re-processes "
                    "the entire context on every message. This burns tokens fast."
                ),
                file_path=str(path),
                remediation=(
                    "Set context.softThresholdTokens (e.g. 40000) or enable memoryFlush "
                    "to auto-compact long sessions."
                ),
            ))
        return findings

    def _check_no_cache_ttl(self, path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        agents = data.get("agents", data.get("agent", {}))
        if not isinstance(agents, dict):
            return findings

        defaults = agents.get("defaults", agents)
        if not isinstance(defaults, dict):
            return findings

        cache = defaults.get("cache", defaults.get("cache-ttl", {}))
        if not cache or (isinstance(cache, dict) and not cache.get("mode")):
            findings.append(Finding(
                id=f"BURN-{len(findings) + 1:03d}",
                title="No prompt cache TTL configured",
                severity=Severity.LOW,
                module=self.name,
                description=(
                    "No cache-ttl configured. Anthropic and OpenAI support prompt caching "
                    "that can reduce costs 50-90% on repeated context. Without it, "
                    "you pay full price for re-processing the same system prompt every time."
                ),
                file_path=str(path),
                remediation='Set cache-ttl mode in config (e.g. cache.mode: "6h").',
            ))
        return findings

    def _check_expensive_embeddings(self, path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        agents = data.get("agents", data.get("agent", {}))
        if not isinstance(agents, dict):
            return findings

        defaults = agents.get("defaults", agents)
        if not isinstance(defaults, dict):
            return findings

        embeddings = defaults.get("embeddings", {})
        if isinstance(embeddings, dict):
            model = embeddings.get("model", "")
            if model and any(exp in model for exp in ["large", "3-large", "ada-002"]):
                findings.append(Finding(
                    id=f"BURN-{len(findings) + 1:03d}",
                    title=f"Expensive embedding model: {model}",
                    severity=Severity.LOW,
                    module=self.name,
                    description=(
                        f"Embedding model '{model}' is more expensive than needed. "
                        "For memory search, text-embedding-3-small works just as well "
                        "at a fraction of the cost."
                    ),
                    file_path=str(path),
                    remediation='Use "text-embedding-3-small" or local embeddings.',
                ))
        return findings

    def _check_cron_models(self, path, data: dict) -> list[Finding]:
        findings: list[Finding] = []
        crons = data.get("crons", data.get("cron", {}))
        if not isinstance(crons, dict):
            return findings

        for cron_name, cron_cfg in crons.items():
            if not isinstance(cron_cfg, dict):
                continue
            model = cron_cfg.get("model", "")
            if model and self._is_expensive(model):
                findings.append(Finding(
                    id=f"BURN-{len(findings) + 1:03d}",
                    title=f"Expensive model in cron '{cron_name}': {model}",
                    severity=Severity.MEDIUM,
                    module=self.name,
                    description=(
                        f"Cron job '{cron_name}' uses expensive model '{model}'. "
                        "Crons run automatically and repeatedly — expensive models "
                        "in crons cause silent budget drain."
                    ),
                    file_path=str(path),
                    remediation=f"Switch cron '{cron_name}' to a cheaper model (haiku, gpt-5-mini, qwen-flash).",
                ))
        return findings
