"""Wrappers around Kali Linux tooling and external services."""

from netmon.integrations.kali_tools import KaliTools
from netmon.integrations.ollama import OllamaClient

__all__ = ["KaliTools", "OllamaClient"]
