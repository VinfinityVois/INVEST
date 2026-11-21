from collections import defaultdict, deque
from datetime import datetime, timezone
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from time import perf_counter

from app.config import settings
from app.rules_loader import rule_packs
from app.ai.explanations import explain_findings
from app.notifications.webhook import WebhookDeliveryError, build_notification_payload, deliver_webhook
from app.notifications.telegram import TelegramDeliveryError, deliver_telegram
from app.notifications.email import EmailDeliveryError, deliver_email
from app.policies.security_gate import evaluate_security_gate
from app.scanners.secrets import scan_directory
from app.scanners.presentation import enrich_finding
from app.scanners.sca import scan_project
from app.scanners.sast import scan_kotlin_project
from app.sources.git import GitSourceError, clone_allowed_repository
from app.sources.project_root import detect_project_root
from .registry import NodeRegistry
from .schemas import WorkflowGraph
from .validator import validate_graph
from .engine_runtime import execute_graph as _execute_graph_impl


class WorkflowExecutionError(RuntimeError):
    pass


def execute_graph(*args, **kwargs):
    return _execute_graph_impl(*args, **kwargs)
