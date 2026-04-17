"""
Scouter — The AI Permission Layer
Runtime Semantic Authorization SDK for Python.
"""

__version__ = "0.4.0-alpha"

from scouter.client import ScouterClient
from scouter.engine.intent import IntentRegistry
from scouter.engine.consequence import ConsequenceEngine
from scouter.classifier.action_triage import ActionTriageClassifier
from scouter.guards.execution_interceptor import ExecutionInterceptor
from scouter.guards.shell_guard import ShellGuard
from scouter.guards.database_guard import DatabaseGuard
from scouter.guards.api_guard import APIGuard
from scouter.guards.light_guard import LightGuard
from scouter.guards.base import GuardDecision, GuardResult, BaseGuard
from scouter.api.backend import BackendClient

__all__ = [
    "ScouterClient",
    "IntentRegistry",
    "ConsequenceEngine",
    "ActionTriageClassifier",
    "ExecutionInterceptor",
    "ShellGuard",
    "DatabaseGuard",
    "APIGuard",
    "LightGuard",
    "BaseGuard",
    "GuardDecision",
    "GuardResult",
    "BackendClient",
]
