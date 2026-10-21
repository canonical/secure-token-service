"""OpenSpec integration package for Google's harness2 in secure-token-service."""

from .adapter import OpenSpecAdapter
from .proposer import OpenSpecScriptedProposer

__all__ = ["OpenSpecAdapter", "OpenSpecScriptedProposer"]
