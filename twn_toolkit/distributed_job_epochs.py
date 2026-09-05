"""Compatibility import for the activation-aware distributed queue.

Activation binding and claims now share the transaction implementation in
``distributed_jobs``. Keep this import path for existing integrations.
"""

from .distributed_jobs import DistributedJobStore


__all__ = ["DistributedJobStore"]
