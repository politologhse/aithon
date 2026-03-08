"""Network exposure detection."""
import subprocess
import re
from aithon.modules.base import BaseModule
from aithon.core.finding import Finding
from aithon.config import Severity


class NetworkModule(BaseModule):

    @property
    def name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Detects exposed network ports and unsecured agent endpoints"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        agent_ports = self.agent.get_known_ports()

        try:
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=5,
            )
            listening = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                result = subprocess.run(
                    ["netstat", "-tlnp"], capture_output=True, text=True, timeout=5,
                )
                listening = result.stdout
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return findings

        for port, service_name in agent_ports.items():
            pattern = rf"0\.0\.0\.0:{port}\s"
            if re.search(pattern, listening):
                findings.append(Finding(
                    id=f"NET-{len(findings) + 1:03d}",
                    title=f"{service_name} exposed on all interfaces (port {port})",
                    severity=Severity.HIGH,
                    module=self.name,
                    description=(
                        f"Service '{service_name}' is listening on 0.0.0.0:{port}, "
                        "making it accessible from any network interface. "
                        "Agent admin panels and API endpoints should only bind to localhost."
                    ),
                    evidence=f"0.0.0.0:{port}",
                    remediation=f"Bind to 127.0.0.1:{port} instead of 0.0.0.0:{port}",
                ))

            pattern6 = rf":::{port}\s"
            if re.search(pattern6, listening):
                findings.append(Finding(
                    id=f"NET-{len(findings) + 1:03d}",
                    title=f"{service_name} exposed on all IPv6 interfaces (port {port})",
                    severity=Severity.HIGH,
                    module=self.name,
                    description=(
                        f"Service '{service_name}' is listening on [::]:{port} (all IPv6). "
                        "Restrict to localhost."
                    ),
                    evidence=f":::{port}",
                    remediation=f"Bind to [::1]:{port} or 127.0.0.1:{port}",
                ))

        return findings
