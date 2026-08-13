from __future__ import annotations

import hashlib
import json
import re
import tempfile
import zipfile
from datetime import datetime, timezone
from html import escape
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .datastore import DatastoreError
from .version import APP_VERSION


PACKAGE_SCHEMA = "twn.case-package.v1"
PDF_FILENAME = "case-report.pdf"
MANIFEST_FILENAME = "manifest.json"
_PAGE_WIDTH = letter[0] - 1.1 * inch
_GREEN = colors.HexColor("#245d45")
_GREEN_LINE = colors.HexColor("#2f7656")
_RED = colors.HexColor("#d8323c")
_INK = colors.HexColor("#19211f")
_MUTED = colors.HexColor("#5d6966")
_LINE = colors.HexColor("#d9dfdc")
_SOFT = colors.HexColor("#f5f7f6")


class InvestigationExportError(RuntimeError):
    pass


def build_case_report_pdf(
    investigation: dict[str, Any], report: dict[str, Any]
) -> bytes:
    """Render the saved case-report selection as a deterministic PDF."""
    _register_fonts()
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
        title=_plain(investigation.get("title")),
        author="The WiFi Ninja's Toolkit",
        subject="Troubleshooting case report",
    )
    styles = _styles()
    story: list[Any] = []
    story.extend(_title_story(investigation, report, styles))
    story.extend(_timeline_story(report, styles))
    story.extend(_result_story(report, styles))
    story.extend(_evidence_story(report, styles))
    document.build(
        story,
        onFirstPage=lambda canvas, doc: _page_footer(
            canvas, doc, investigation
        ),
        onLaterPages=lambda canvas, doc: _page_footer(
            canvas, doc, investigation
        ),
    )
    return output.getvalue()


def build_case_package(
    *,
    store: Any,
    investigation: dict[str, Any],
    report: dict[str, Any],
    generated_at: datetime | None = None,
) -> tuple[BinaryIO, dict[str, Any]]:
    """Build a temporary ZIP containing the selected report and evidence."""
    pdf = build_case_report_pdf(investigation, report)
    archive = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b")
    timestamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    evidence_manifest: list[dict[str, Any]] = []
    used_names: set[str] = set()
    try:
        with zipfile.ZipFile(
            archive,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            allowZip64=True,
        ) as bundle:
            bundle.writestr(PDF_FILENAME, pdf)
            for artifact in report["report_artifacts"]:
                source = store.datastore.file(str(artifact["relative_path"]))
                filename = _unique_evidence_name(
                    str(artifact["display_name"]), used_names
                )
                member_name = f"evidence/{filename}"
                digest = hashlib.sha256()
                byte_count = 0
                with source.open("rb") as input_stream, bundle.open(
                    member_name, "w"
                ) as output_stream:
                    for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                        byte_count += len(chunk)
                        output_stream.write(chunk)
                actual_digest = digest.hexdigest()
                if (
                    byte_count != int(artifact["byte_count"])
                    or actual_digest != str(artifact["sha256"])
                ):
                    raise InvestigationExportError(
                        f"Evidence file {artifact['display_name']} has changed since upload."
                    )
                evidence_manifest.append(
                    {
                        "id": artifact["id"],
                        "filename": member_name,
                        "display_name": artifact["display_name"],
                        "content_type": artifact["content_type"],
                        "byte_count": byte_count,
                        "sha256": actual_digest,
                        "collected_at": _iso_time(artifact["created_at"]),
                    }
                )
            manifest = _case_manifest(
                investigation,
                report,
                pdf,
                evidence_manifest,
                timestamp,
            )
            bundle.writestr(
                MANIFEST_FILENAME,
                json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False)
                + "\n",
            )
        archive.seek(0)
        return archive, manifest
    except (DatastoreError, OSError, KeyError, TypeError, ValueError):
        archive.close()
        raise
    except BaseException:
        archive.close()
        raise


def case_package_filename(investigation: dict[str, Any]) -> str:
    return f"{_filename_stem(investigation)}.zip"


def case_report_filename(investigation: dict[str, Any]) -> str:
    return f"{_filename_stem(investigation)}.pdf"


def _filename_stem(investigation: dict[str, Any]) -> str:
    title = re.sub(
        r"[^A-Za-z0-9._-]+", "-", _plain(investigation.get("title")).strip()
    ).strip("-._")[:80]
    return f"{title or 'case'}-{investigation['id']}"


def _title_story(
    investigation: dict[str, Any],
    report: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    event_count = len(report["report_events"])
    artifact_count = len(report["report_artifacts"])
    contents = [
        Paragraph("CASE REPORT", styles["eyebrow"]),
        Paragraph(_markup(investigation["title"]), styles["title"]),
    ]
    if investigation.get("description"):
        contents.append(
            Paragraph(_markup(investigation["description"]), styles["description"])
        )
    meta = [
        ("STARTED", investigation["started_display"]),
        ("STATUS", investigation["state_label"]),
        ("OWNER", investigation["owner_username"]),
        ("OPERATORS", investigation.get("operator_names", investigation["owner_username"])),
        (
            "INCLUDED",
            f"{event_count} timeline {_word(event_count, 'entry', 'entries')} | "
            f"{artifact_count} {_word(artifact_count, 'file', 'files')}",
        ),
    ]
    cells = [
        [
            Paragraph(_markup(label), styles["meta_label"]),
            Paragraph(_markup(value), styles["meta_value"]),
        ]
        for label, value in meta
    ]
    table = Table(
        [[cell for cell in cells]],
        colWidths=[_PAGE_WIDTH / len(cells)] * len(cells),
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _SOFT),
                ("BOX", (0, 0), (-1, -1), 0.5, _LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, _LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        ),
    )
    contents.extend([Spacer(1, 8), table, Spacer(1, 12)])
    return contents


def _timeline_story(
    report: dict[str, Any], styles: dict[str, ParagraphStyle]
) -> list[Any]:
    story: list[Any] = [
        Paragraph('<a name="case-timeline"/>Case timeline', styles["section"]),
        Spacer(1, 3),
    ]
    if not report["report_events"]:
        story.append(
            Paragraph("No timeline entries are included in this report.", styles["body"])
        )
        return story
    for event in report["report_events"]:
        event_id = str(event["id"])
        presentation = report["event_presentations"][event_id]
        heading = (
            f'<font color="#5d6966" size="7">{_markup(event["started_display"])}</font> '
            f"<b>{_markup(event['action'])}</b>"
        )
        content: list[Any] = [
            Paragraph(heading, styles["timeline_heading"]),
            Paragraph(_markup(event["summary"]), styles["timeline_summary"]),
        ]
        if presentation["facts"]:
            facts = "&nbsp;&nbsp;&nbsp;".join(
                f'<font color="#5d6966" size="6"><b>{_markup(fact["label"]).upper()}</b></font> '
                f"<b>{_markup(fact['value'])}</b>"
                for fact in presentation["facts"]
            )
            content.append(Paragraph(facts, styles["facts"]))
        if event_id in report["report_result_labels"]:
            label = report["report_result_labels"][event_id]
            content.append(
                Paragraph(
                    f'<link href="#result-{event_id}" color="#245d45">'
                    f"<u>Detailed results {_markup(label)}</u> -&gt;</link>",
                    styles["result_link"],
                )
            )
        outcome = _plain(event["outcome"])
        event_table = Table(
            [[content, Paragraph(_markup(outcome), styles["outcome"])]],
            colWidths=[_PAGE_WIDTH - 60, 60],
            style=TableStyle(
                [
                    ("LINEBEFORE", (0, 0), (0, -1), 2, _GREEN_LINE),
                    ("LINEBELOW", (0, -1), (-1, -1), 0.4, _LINE),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (0, -1), 8),
                    ("RIGHTPADDING", (0, 0), (0, -1), 4),
                    ("LEFTPADDING", (1, 0), (1, -1), 3),
                    ("RIGHTPADDING", (1, 0), (1, -1), 3),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            ),
        )
        story.append(KeepTogether([event_table]))
    return story


def _result_story(
    report: dict[str, Any], styles: dict[str, ParagraphStyle]
) -> list[Any]:
    story: list[Any] = []
    for event in report["report_result_events"]:
        event_id = str(event["id"])
        label = report["report_result_labels"][event_id]
        detail = report["event_presentations"][event_id]["detail"]
        story.extend(
            [
                PageBreak(),
                Paragraph(
                    f'<a name="result-{event_id}"/>DETAILED RESULTS | {_markup(label)}',
                    styles["eyebrow"],
                ),
                Paragraph(_markup(event["action"]), styles["result_title"]),
                Paragraph(
                    f"{_markup(event['started_display'])} | {_markup(event['outcome'])}",
                    styles["result_meta"],
                ),
                Paragraph(
                    '<link href="#case-timeline" color="#245d45">'
                    "<u>Back to timeline</u></link>",
                    styles["back_link"],
                ),
                Spacer(1, 8),
                Paragraph(_markup(event["summary"]), styles["result_summary"]),
                Spacer(1, 5),
            ]
        )
        if detail["kind"] == "table":
            story.append(_detail_table(detail, styles))
        elif detail["kind"] == "metrics":
            story.append(_metric_table(detail, styles))
    return story


def _evidence_story(
    report: dict[str, Any], styles: dict[str, ParagraphStyle]
) -> list[Any]:
    if not report["report_artifacts"]:
        return []
    data = [
        [
            Paragraph("FILE", styles["table_header"]),
            Paragraph("COLLECTED", styles["table_header"]),
            Paragraph("SIZE", styles["table_header"]),
            Paragraph("SHA-256", styles["table_header"]),
        ]
    ]
    for artifact in report["report_artifacts"]:
        digest = "<br/>".join(
            escape(str(artifact["sha256"])[index : index + 16])
            for index in range(0, len(str(artifact["sha256"])), 16)
        )
        data.append(
            [
                Paragraph(_markup(artifact["display_name"]), styles["table_cell"]),
                Paragraph(_markup(artifact["created_display"]), styles["table_cell"]),
                Paragraph(
                    _markup(_format_bytes(int(artifact["byte_count"]))),
                    styles["table_cell"],
                ),
                Paragraph(digest, styles["mono_cell"]),
            ]
        )
    table = LongTable(
        data,
        colWidths=[120, 105, 55, _PAGE_WIDTH - 280],
        repeatRows=1,
        hAlign="LEFT",
        style=_table_style(),
    )
    return [
        PageBreak(),
        Paragraph("Evidence appendix", styles["section"]),
        Spacer(1, 5),
        table,
    ]


def _detail_table(
    detail: dict[str, Any], styles: dict[str, ParagraphStyle]
) -> LongTable:
    rows = [
        [Paragraph(_markup(column).upper(), styles["table_header"]) for column in detail["columns"]]
    ]
    rows.extend(
        [Paragraph(_markup(cell), styles["table_cell"]) for cell in row]
        for row in detail["rows"]
    )
    return LongTable(
        rows,
        colWidths=_column_widths(detail["columns"], detail["rows"]),
        repeatRows=1,
        hAlign="LEFT",
        style=_table_style(),
    )


def _metric_table(
    detail: dict[str, Any], styles: dict[str, ParagraphStyle]
) -> Table:
    cells = [
        [
            Paragraph(_markup(metric["label"]).upper(), styles["meta_label"]),
            Paragraph(_markup(metric["value"]), styles["meta_value"]),
        ]
        for metric in detail["values"]
    ]
    widths = [_PAGE_WIDTH / max(1, len(cells))] * len(cells)
    return Table(
        [[cell for cell in cells]],
        colWidths=widths,
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _SOFT),
                ("BOX", (0, 0), (-1, -1), 0.5, _LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, _LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        ),
    )


def _case_manifest(
    investigation: dict[str, Any],
    report: dict[str, Any],
    pdf: bytes,
    evidence: list[dict[str, Any]],
    generated_at: datetime,
) -> dict[str, Any]:
    labels = report["report_result_labels"]
    return {
        "schema": PACKAGE_SCHEMA,
        "toolkit_version": APP_VERSION,
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "case": {
            "id": investigation["id"],
            "title": investigation["title"],
            "description": investigation["description"],
            "state": investigation["state"],
            "operator": investigation["owner_username"],
            "operators": [
                {
                    "user_id": participant["user_id"],
                    "username": participant["username"],
                    "role": participant["role"],
                }
                for participant in investigation.get("participants", [])
            ],
            "started_at": _iso_time(investigation["started_at"]),
            "ended_at": (
                _iso_time(investigation["ended_at"])
                if investigation.get("ended_at") is not None
                else None
            ),
        },
        "report": {
            "filename": PDF_FILENAME,
            "byte_count": len(pdf),
            "sha256": hashlib.sha256(pdf).hexdigest(),
            "timeline_entry_count": len(report["report_events"]),
            "detailed_result_count": len(report["report_result_events"]),
        },
        "timeline": [
            {
                "id": event["id"],
                "event_type": event["event_type"],
                "tool_id": event["tool_id"],
                "action": event["action"],
                "outcome": event["outcome"],
                "started_at": _iso_time(event["started_at"]),
                "completed_at": _iso_time(event["completed_at"]),
                "detailed_result_label": labels.get(str(event["id"])),
            }
            for event in report["report_events"]
        ],
        "evidence": evidence,
    }


def _styles() -> dict[str, ParagraphStyle]:
    sample = getSampleStyleSheet()
    return {
        "eyebrow": ParagraphStyle(
            "CaseEyebrow",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=8,
            leading=10,
            textColor=_RED,
            spaceAfter=4,
        ),
        "title": ParagraphStyle(
            "CaseTitle",
            parent=sample["Title"],
            fontName="TWN-Bold",
            fontSize=23,
            leading=27,
            textColor=_INK,
            alignment=0,
            spaceAfter=5,
        ),
        "description": ParagraphStyle(
            "CaseDescription",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=9,
            leading=12,
            textColor=_MUTED,
            spaceAfter=2,
        ),
        "meta_label": ParagraphStyle(
            "CaseMetaLabel",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=6,
            leading=7,
            textColor=_MUTED,
        ),
        "meta_value": ParagraphStyle(
            "CaseMetaValue",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=8,
            leading=9.5,
            textColor=_INK,
            spaceBefore=2,
        ),
        "section": ParagraphStyle(
            "CaseSection",
            parent=sample["Heading2"],
            fontName="TWN-Bold",
            fontSize=12,
            leading=14,
            textColor=_INK,
            spaceBefore=2,
            spaceAfter=2,
        ),
        "body": ParagraphStyle(
            "CaseBody",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=8.5,
            leading=11,
            textColor=_INK,
        ),
        "timeline_heading": ParagraphStyle(
            "CaseTimelineHeading",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=9.5,
            leading=11,
            textColor=_INK,
        ),
        "timeline_summary": ParagraphStyle(
            "CaseTimelineSummary",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=8,
            leading=9.5,
            textColor=_MUTED,
            spaceBefore=1,
        ),
        "facts": ParagraphStyle(
            "CaseFacts",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=7,
            leading=8.5,
            textColor=_INK,
            spaceBefore=1,
        ),
        "result_link": ParagraphStyle(
            "CaseResultLink",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=7,
            leading=8.5,
            textColor=_GREEN,
            spaceBefore=1,
        ),
        "outcome": ParagraphStyle(
            "CaseOutcome",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=6.5,
            leading=8,
            alignment=TA_RIGHT,
            textColor=_GREEN,
        ),
        "result_title": ParagraphStyle(
            "CaseResultTitle",
            parent=sample["Heading2"],
            fontName="TWN-Bold",
            fontSize=12,
            leading=14,
            textColor=_INK,
            spaceAfter=2,
        ),
        "result_meta": ParagraphStyle(
            "CaseResultMeta",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=8,
            leading=10,
            textColor=_MUTED,
        ),
        "back_link": ParagraphStyle(
            "CaseBackLink",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=7.5,
            leading=9,
            alignment=TA_RIGHT,
            textColor=_GREEN,
            spaceBefore=-10,
        ),
        "result_summary": ParagraphStyle(
            "CaseResultSummary",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=9,
            leading=12,
            textColor=_MUTED,
        ),
        "table_header": ParagraphStyle(
            "CaseTableHeader",
            parent=sample["Normal"],
            fontName="TWN-Bold",
            fontSize=7,
            leading=8.5,
            textColor=colors.HexColor("#344052"),
        ),
        "table_cell": ParagraphStyle(
            "CaseTableCell",
            parent=sample["Normal"],
            fontName="TWN-Regular",
            fontSize=7,
            leading=8.5,
            textColor=_INK,
        ),
        "mono_cell": ParagraphStyle(
            "CaseMonoCell",
            parent=sample["Normal"],
            fontName="Courier",
            fontSize=6.5,
            leading=8,
            textColor=_INK,
        ),
    }


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, _LINE),
            ("BACKGROUND", (0, 0), (-1, 0), _SOFT),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def _column_widths(columns: list[str], rows: list[list[str]]) -> list[float]:
    weights = []
    for index, column in enumerate(columns):
        values = [str(row[index]) for row in rows[:100] if index < len(row)]
        value_lengths = [
            max((len(line) for line in value.splitlines()), default=0)
            for value in values
        ]
        longest = max([len(str(column)), *value_lengths])
        weights.append(min(28.0, max(7.0, float(longest))))
    total = sum(weights) or 1
    return [_PAGE_WIDTH * weight / total for weight in weights]


def _register_fonts() -> None:
    if "TWN-Regular" in pdfmetrics.getRegisteredFontNames():
        return
    font_root = Path(__import__("reportlab").__file__).resolve().parent / "fonts"
    pdfmetrics.registerFont(TTFont("TWN-Regular", str(font_root / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont("TWN-Bold", str(font_root / "VeraBd.ttf")))


def _page_footer(canvas: Any, document: Any, investigation: dict[str, Any]) -> None:
    canvas.saveState()
    canvas.setStrokeColor(_LINE)
    canvas.setLineWidth(0.5)
    canvas.line(0.55 * inch, 0.42 * inch, letter[0] - 0.55 * inch, 0.42 * inch)
    canvas.setFont("TWN-Regular", 6.5)
    canvas.setFillColor(_MUTED)
    canvas.drawString(
        0.55 * inch,
        0.25 * inch,
        f"Case {_plain(investigation['id'])}",
    )
    canvas.drawRightString(
        letter[0] - 0.55 * inch,
        0.25 * inch,
        f"Page {document.page}",
    )
    canvas.restoreState()


def _unique_evidence_name(name: str, used: set[str]) -> str:
    clean = Path(name).name.strip()[:240] or "evidence.bin"
    candidate = clean
    stem = Path(clean).stem
    suffix = Path(clean).suffix
    index = 2
    while candidate.casefold() in used:
        candidate = f"{stem[:220]}-{index}{suffix[:20]}"
        index += 1
    used.add(candidate.casefold())
    return candidate


def _markup(value: Any) -> str:
    return escape(_plain(value)).replace("\n", "<br/>")


def _plain(value: Any) -> str:
    text = str(value or "")
    return (
        text.replace("\u2011", "-")
        .replace("\u2013", "-")
        .replace("\u2014", "-")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2022", "|")
        .replace("\u2192", "->")
    )


def _word(count: int, singular: str, plural: str) -> str:
    return singular if count == 1 else plural


def _iso_time(value: Any) -> str:
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} bytes"
    if value < 1024**2:
        return f"{value / 1024:.1f} KiB"
    if value < 1024**3:
        return f"{value / 1024**2:.1f} MiB"
    return f"{value / 1024**3:.1f} GiB"
