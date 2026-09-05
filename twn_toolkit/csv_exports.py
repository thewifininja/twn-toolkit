"""CSV rendering helpers for browser downloads.

The toolkit keeps generated evidence and explicit raw downloads lossless. The
default browser download is rendered separately so a spreadsheet does not
interpret device-supplied text as a formula.
"""

from __future__ import annotations

import csv
import io
import re


CSV_DOWNLOAD_FORMAT_SPREADSHEET = "spreadsheet"
CSV_DOWNLOAD_FORMAT_RAW = "raw"

_FORMULA_PREFIXES = ("=", "+", "-", "@")
_FORMULA_LEADING_WHITESPACE = " \t\r\n"
_NUMBER = re.compile(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d)?\Z")


def normalize_csv_download_format(value: str | None) -> str:
    """Return a recognized download format, defaulting to spreadsheet-safe CSV."""
    if value == CSV_DOWNLOAD_FORMAT_RAW:
        return CSV_DOWNLOAD_FORMAT_RAW
    return CSV_DOWNLOAD_FORMAT_SPREADSHEET


def csv_download_filename(filename: str, download_format: str) -> str:
    """Mark the CSV's intended consumer in its download filename."""
    stem = filename[:-4] if filename.lower().endswith(".csv") else filename
    suffix = "-raw.csv" if download_format == CSV_DOWNLOAD_FORMAT_RAW else "-spreadsheet.csv"
    return f"{stem}{suffix}"


def csv_for_download(raw_csv: str, download_format: str) -> str:
    """Return a raw or spreadsheet-safe copy of a lossless CSV document."""
    if normalize_csv_download_format(download_format) == CSV_DOWNLOAD_FORMAT_RAW:
        return raw_csv
    return spreadsheet_safe_csv(raw_csv)


def spreadsheet_safe_csv(raw_csv: str) -> str:
    """Escape formula-looking textual cells without changing ordinary CSV data.

    Spreadsheet applications may evaluate a value beginning with a formula
    marker even if whitespace precedes it. A leading apostrophe makes that
    value literal. Signed numeric values are retained because they are data,
    not formulas. When no cell needs escaping, preserve the original bytes
    exactly, including quoting and line endings.
    """
    reader = csv.reader(io.StringIO(raw_csv, newline=""))
    rows = list(reader)
    safe_rows = [[_spreadsheet_safe_cell(value) for value in row] for row in rows]
    if safe_rows == rows:
        return raw_csv

    output = io.StringIO(newline="")
    writer = csv.writer(
        output,
        lineterminator="\r\n" if "\r\n" in raw_csv else "\n",
    )
    writer.writerows(safe_rows)
    return output.getvalue()


def _spreadsheet_safe_cell(value: str) -> str:
    formula_candidate = value.lstrip(_FORMULA_LEADING_WHITESPACE)
    if formula_candidate.startswith(_FORMULA_PREFIXES) and not _NUMBER.fullmatch(value):
        return f"'{value}"
    return value
