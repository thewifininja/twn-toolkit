"""Operator policy and internal envelope bounds for finite diagnostics."""
DIAGNOSTIC_LIMITS = {
    "diagnostic_case_export_input_mib": (16, 1, 64, "Case export input limit (MiB)"),
    "diagnostic_case_export_max_mib": (128, 1, 1024, "Case export file limit (MiB)"),
    "diagnostic_case_export_pdf_cells": (50000, 1000, 200000, "Case PDF detail-cell limit"),
    "diagnostic_artifact_max_mib": (128, 1, 1024, "Inventory export file limit (MiB)"),
    "diagnostic_workers": (2, 1, 8, "Concurrent diagnostic runs"),
    "diagnostic_queue_limit": (32, 1, 200, "Queued diagnostic runs"),
    "diagnostic_user_limit": (4, 1, 200, "Active diagnostic runs per user"),
    "diagnostic_timeout_seconds": (300, 5, 3600, "Diagnostic deadline (seconds)"),
    "diagnostic_history_limit": (128, 1, 10000, "Retained diagnostic runs"),
    "diagnostic_retention_hours": (24, 1, 720, "Diagnostic retention (hours)"),
}
MAX_RESULT_ROWS = 5000
MAX_RESULT_BYTES = 8 * 1024 * 1024
RESULT_PAGE_SIZE = 100


def validate_diagnostic_limits(values):
    result = {}
    for key, (default, low, high, label) in DIAGNOSTIC_LIMITS.items():
        raw = values.get(key, default)
        if isinstance(raw, bool) or not isinstance(raw, (str, int)):
            raise ValueError(f"{label} must be a whole number.")
        try:
            number = int(raw)
        except ValueError as exc:
            raise ValueError(f"{label} must be a whole number.") from exc
        if not low <= number <= high:
            raise ValueError(f"{label} must be {low}–{high}.")
        result[key] = number
    return result
