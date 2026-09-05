from __future__ import annotations

import csv
import io
import unittest

from twn_toolkit.csv_exports import (
    CSV_DOWNLOAD_FORMAT_RAW,
    CSV_DOWNLOAD_FORMAT_SPREADSHEET,
    csv_download_filename,
    csv_for_download,
    normalize_csv_download_format,
    spreadsheet_safe_csv,
)


class CsvExportTests(unittest.TestCase):
    def test_spreadsheet_copy_escapes_formula_text_and_preserves_numbers(self) -> None:
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(["=header", "number", "text"])
        writer.writerow(["=SUM(A1:A2)", "-1", "+command"])
        writer.writerow(["\t@command", "+1.25", "\n-danger"])
        writer.writerow(["\r=command", "-.5", "@command"])
        raw_csv = output.getvalue()

        safe_rows = list(csv.reader(io.StringIO(spreadsheet_safe_csv(raw_csv), newline="")))

        self.assertEqual(
            safe_rows,
            [
                ["'=header", "number", "text"],
                ["'=SUM(A1:A2)", "-1", "'+command"],
                ["'\t@command", "+1.25", "'\n-danger"],
                ["'\r=command", "-.5", "'@command"],
            ],
        )

    def test_safe_copy_preserves_benign_csv_exactly(self) -> None:
        raw_csv = 'name,description\r\nPrinter,"Front office, east wing"\r\n'
        self.assertEqual(spreadsheet_safe_csv(raw_csv), raw_csv)

    def test_download_formats_keep_raw_csv_explicit(self) -> None:
        raw_csv = "name\n=command\n"

        self.assertEqual(normalize_csv_download_format(None), CSV_DOWNLOAD_FORMAT_SPREADSHEET)
        self.assertEqual(normalize_csv_download_format("unexpected"), CSV_DOWNLOAD_FORMAT_SPREADSHEET)
        self.assertEqual(normalize_csv_download_format("raw"), CSV_DOWNLOAD_FORMAT_RAW)
        self.assertEqual(csv_for_download(raw_csv, CSV_DOWNLOAD_FORMAT_RAW), raw_csv)
        self.assertEqual(csv_for_download(raw_csv, CSV_DOWNLOAD_FORMAT_SPREADSHEET), "name\n'=command\n")
        self.assertEqual(
            csv_download_filename("devices.csv", CSV_DOWNLOAD_FORMAT_SPREADSHEET),
            "devices-spreadsheet.csv",
        )
        self.assertEqual(
            csv_download_filename("devices.csv", CSV_DOWNLOAD_FORMAT_RAW),
            "devices-raw.csv",
        )


if __name__ == "__main__":
    unittest.main()
