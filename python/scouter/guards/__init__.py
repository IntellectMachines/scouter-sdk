"""
Scouter Execution Guards — Intercept dangerous actions at the execution layer.

Guard types:
  - ShellGuard:    Intercepts shell/subprocess commands
  - DatabaseGuard: Intercepts SQL queries
  - APIGuard:      Intercepts outbound HTTP requests

Hybrid architecture:
  - LightGuard:    Ultra-fast client-side keyword check (passes 99%)
  - ServerGuard:   Sends suspicious ~1% to server for full validation
"""

from scouter.guards.base import GuardDecision, GuardResult, BaseGuard
from scouter.guards.shell_guard import ShellGuard
from scouter.guards.database_guard import DatabaseGuard
from scouter.guards.api_guard import APIGuard
from scouter.guards.light_guard import LightGuard
from scouter.guards.server_guard import ServerGuard
from scouter.guards.execution_interceptor import ExecutionInterceptor

__all__ = [
    "ShellGuard",
    "DatabaseGuard",
    "APIGuard",
    "LightGuard",
    "ServerGuard",
    "ExecutionInterceptor",
    "GuardDecision",
    "GuardResult",
    "BaseGuard",
]
