from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

import fcntl


@dataclass(frozen=True)
class RankDefinition:
    counter: str
    label: str
    unit: str


@dataclass(frozen=True)
class MetricDefinition:
    key: str
    counters: tuple[str, ...]
    kicker: str
    title: str
    primary_counter: str
    primary_label: str
    secondary_template: str
    ranks: tuple[RankDefinition, ...]


METRIC_DEFINITIONS: tuple[MetricDefinition, ...] = (
    MetricDefinition(
        "ping", ("probes_sent", "replies_received"), "Reachability", "Ping probes",
        "probes_sent", "sent", "{replies_received} replies",
        (
            RankDefinition("probes_sent", "Ping probes sent", "sent"),
            RankDefinition("replies_received", "Ping replies", "replies"),
        ),
    ),
    MetricDefinition(
        "snmp", ("polls",), "Infrastructure", "SNMP polls", "polls", "polls",
        "GET and walk activity", (RankDefinition("polls", "SNMP polls", "polls"),),
    ),
    MetricDefinition(
        "fortinet", ("api_calls", "failures"), "Fortinet", "API activity", "api_calls",
        "calls", "{failures} failures",
        (RankDefinition("api_calls", "Fortinet API calls", "calls"),),
    ),
    MetricDefinition(
        "traceroute", ("completed", "hops"), "Pathing", "Traceroutes", "completed",
        "completed", "{hops} total hops",
        (RankDefinition("completed", "Traceroutes completed", "completed"),),
    ),
    MetricDefinition(
        "radius", ("attempts",), "Authentication", "RADIUS", "attempts", "attempts",
        "PAP, CHAP, PEAP, and EAP-TLS",
        (RankDefinition("attempts", "RADIUS attempts", "attempts"),),
    ),
    MetricDefinition(
        "packet_replay", ("frames",), "Packets", "Packet replay", "frames", "frames",
        "Accepted for raw transmission",
        (RankDefinition("frames", "Packet replay frames", "frames"),),
    ),
    MetricDefinition(
        "syslog", ("messages",), "Logging", "Syslog", "messages", "messages",
        "Sent or received messages",
        (RankDefinition("messages", "Syslog messages", "messages"),),
    ),
    MetricDefinition(
        "dns", ("queries",), "Resolution", "DNS", "queries", "queries",
        "Host and resolver lookups", (RankDefinition("queries", "DNS queries", "queries"),),
    ),
    MetricDefinition(
        "speedtest", ("runs", "bytes_transferred"), "Throughput", "Speed tests", "runs", "runs",
        "{bytes_transferred_display} transferred", (RankDefinition("runs", "Speed tests", "runs"),),
    ),
    MetricDefinition(
        "tcp", ("ports_scanned",), "Ports", "TCP scans", "ports_scanned", "ports",
        "Connection attempts checked",
        (RankDefinition("ports_scanned", "TCP ports scanned", "ports"),),
    ),
    MetricDefinition(
        "ntp", ("queries",), "Time", "NTP", "queries", "queries",
        "Clock samples requested", (RankDefinition("queries", "NTP queries", "queries"),),
    ),
    MetricDefinition(
        "dhcp", ("discovers", "offers"), "Addressing", "DHCP", "discovers", "discovers",
        "{offers} offers received", (RankDefinition("discovers", "DHCP discovers", "discovers"),),
    ),
    MetricDefinition(
        "certificates", ("inspections",), "TLS", "Certificates", "inspections", "checks",
        "Certificate chains inspected",
        (RankDefinition("inspections", "Certificate inspections", "inspections"),),
    ),
    MetricDefinition(
        "api", ("requests",), "HTTP", "Webhook/API", "requests", "requests",
        "Manual HTTP requests", (RankDefinition("requests", "Webhook/API requests", "requests"),),
    ),
    MetricDefinition(
        "path_mtu", ("tests", "probes"), "Pathing", "Path MTU", "tests", "tests",
        "{probes} packet-size probes", (RankDefinition("tests", "Path MTU tests", "tests"),),
    ),
    MetricDefinition(
        "ssh", ("hosts", "commands"), "Automation", "Multi-SSH", "hosts", "hosts",
        "{commands} command deliveries", (RankDefinition("hosts", "SSH hosts", "hosts"),),
    ),
    MetricDefinition(
        "subnet", ("calculations", "networks"), "Addressing", "Subnet exclusions",
        "calculations", "runs", "{networks} resulting networks",
        (RankDefinition("calculations", "Subnet calculations", "runs"),),
    ),
    MetricDefinition(
        "ip", ("lookups",), "Addressing", "IP checks", "lookups", "checks",
        "Toolkit-facing client address", (RankDefinition("lookups", "IP checks", "checks"),),
    ),
)

DEFAULT_COUNTERS: dict[str, dict[str, int]] = {
    "actions": {"total": 0},
    **{
        metric.key: {counter: 0 for counter in metric.counters}
        for metric in METRIC_DEFINITIONS
    },
}

SCOREBOARD_RANKS: list[dict[str, str]] = [
    {
        "key": "actions.total",
        "label": "Activity score",
        "category": "actions",
        "counter": "total",
        "unit": "actions",
    },
    *[
        {
            "key": f"{metric.key}.{rank.counter}",
            "label": rank.label,
            "category": metric.key,
            "counter": rank.counter,
            "unit": rank.unit,
        }
        for metric in METRIC_DEFINITIONS
        for rank in metric.ranks
    ],
]

ACTIVITY_WINDOWS: tuple[dict[str, Any], ...] = (
    {"key": "hour", "label": "Last hour", "seconds": 60 * 60},
    {"key": "day", "label": "Last 24 hours", "seconds": 24 * 60 * 60},
    {"key": "week", "label": "Last 7 days", "seconds": 7 * 24 * 60 * 60},
    {"key": "month", "label": "Last 30 days", "seconds": 30 * 24 * 60 * 60},
    {"key": "lifetime", "label": "Lifetime", "seconds": None},
    {"key": "custom", "label": "Custom range", "seconds": None},
)


class ActivityStore:
    """SQLite-backed activity ledger with dashboard summaries and JSON migration."""

    def __init__(self, instance_path: str, filename: str = "activity.json") -> None:
        self.instance_path = Path(instance_path)
        legacy_name = Path(filename).name
        self.legacy_path = self.instance_path / legacy_name
        self.path = self.instance_path / f"{Path(legacy_name).stem}.sqlite3"
        self.initialization_lock_path = self.instance_path / f".{self.path.name}.init.lock"

    def summary(
        self,
        scoreboard_rank: str = "actions.total",
        window: str = "lifetime",
        custom_start: str = "",
        custom_end: str = "",
    ) -> dict[str, Any]:
        rank_options = [dict(option) for option in SCOREBOARD_RANKS]
        selected_rank = next(
            (option for option in rank_options if option["key"] == scoreboard_rank),
            rank_options[0],
        )
        selected_window = self._window(window)
        range_start, range_end, range_error = self._time_bounds(
            selected_window, custom_start, custom_end
        )
        with self._connect() as connection:
            counters = self._aggregate_counters(
                connection, range_start=range_start, range_end=range_end
            )
            users = self._aggregate_users(
                connection,
                range_start=range_start,
                range_end=range_end,
                selected_rank=selected_rank,
            )
            recent = self._recent_events(
                connection, range_start=range_start, range_end=range_end
            )
        window_data = dict(selected_window)
        window_data.update(
            {
                "range_start": self._datetime_input_value(range_start)
                if selected_window["key"] == "custom"
                else "",
                "range_end": self._datetime_input_value(range_end)
                if selected_window["key"] == "custom"
                else "",
                "range_label": self._range_label(
                    selected_window, range_start, range_end
                ),
                "error": range_error,
            }
        )
        return {
            "cards": self._dashboard_cards(counters),
            "counters": counters,
            "scoreboard": users,
            "scoreboard_rank": selected_rank,
            "scoreboard_rank_options": rank_options,
            "window": window_data,
            "window_options": [dict(option) for option in ACTIVITY_WINDOWS],
            "recent": recent,
        }

    def increment(
        self,
        category: str,
        counter: str,
        amount: int = 1,
        *,
        user_id: str = "",
        username: str = "",
    ) -> None:
        self._validate_amount(amount)
        with self._connect() as connection, connection:
            self._upsert_user(connection, user_id, username)
            self._insert_sample(
                connection,
                int(time.time()),
                category,
                counter,
                amount,
                user_id,
            )

    def record_event(
        self,
        category: str,
        title: str,
        detail: str = "",
        *,
        counters: dict[str, dict[str, int]] | None = None,
        user_id: str = "",
        username: str = "",
        count_action: bool = False,
    ) -> None:
        for values in (counters or {}).values():
            for amount in values.values():
                self._validate_amount(amount)
        recorded_at = int(time.time())
        with self._connect() as connection, connection:
            self._upsert_user(connection, user_id, username)
            if count_action:
                self._insert_sample(
                    connection, recorded_at, "actions", "total", 1, user_id
                )
            for counter_category, values in (counters or {}).items():
                for counter, amount in values.items():
                    self._insert_sample(
                        connection,
                        recorded_at,
                        counter_category,
                        counter,
                        amount,
                        user_id,
                    )
            connection.execute(
                """
                INSERT INTO activity_events
                    (recorded_at, category, title, detail, user_id, username)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (recorded_at, category, title, detail, user_id, username),
            )

    def reset_metric(self, category: str) -> None:
        with self._connect() as connection, connection:
            known = category in DEFAULT_COUNTERS or connection.execute(
                "SELECT 1 FROM activity_samples WHERE category = ? LIMIT 1",
                (category,),
            ).fetchone()
            if not known:
                raise ValueError("Unknown activity metric.")
            connection.execute(
                "DELETE FROM activity_samples WHERE category = ?", (category,)
            )

    def reset_user_actions(self, user_id: str) -> None:
        with self._connect() as connection, connection:
            if connection.execute(
                "SELECT 1 FROM activity_users WHERE user_id = ?", (user_id,)
            ).fetchone() is None:
                raise ValueError("Unknown activity user.")
            connection.execute(
                """
                DELETE FROM activity_samples
                WHERE user_id = ? AND category = 'actions' AND counter = 'total'
                """,
                (user_id,),
            )

    def reset_all_user_actions(self) -> None:
        with self._connect() as connection, connection:
            connection.execute(
                "DELETE FROM activity_samples WHERE category = 'actions' AND counter = 'total'"
            )

    def clear(self) -> None:
        with self._connect() as connection, connection:
            connection.execute("DELETE FROM activity_samples")
            connection.execute("DELETE FROM activity_events")
            connection.execute("DELETE FROM activity_users")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.instance_path.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            self._ensure_initialized(connection)
            yield connection
        finally:
            self._secure_database_files()
            connection.close()

    def _ensure_initialized(self, connection: sqlite3.Connection) -> None:
        if self._database_initialized(connection):
            return
        with self.initialization_lock_path.open("a+", encoding="utf-8") as lock_handle:
            os.chmod(self.initialization_lock_path, 0o600)
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            try:
                if not self._database_initialized(connection):
                    self._initialize(connection)
            finally:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _database_initialized(self, connection: sqlite3.Connection) -> bool:
        try:
            return connection.execute(
                "SELECT value FROM activity_meta WHERE key = 'legacy_json_imported'"
            ).fetchone() is not None
        except sqlite3.OperationalError:
            return False

    def _initialize(self, connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
                CREATE TABLE IF NOT EXISTS activity_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activity_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    counter TEXT NOT NULL,
                    amount INTEGER NOT NULL CHECK (amount >= 0),
                    user_id TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS activity_samples_time_idx
                    ON activity_samples(recorded_at);
                CREATE INDEX IF NOT EXISTS activity_samples_metric_idx
                    ON activity_samples(category, counter, recorded_at);
                CREATE INDEX IF NOT EXISTS activity_samples_user_idx
                    ON activity_samples(user_id, recorded_at);
                CREATE TABLE IF NOT EXISTS activity_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    user_id TEXT NOT NULL DEFAULT '',
                    username TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS activity_events_time_idx
                    ON activity_events(recorded_at DESC);
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT OR IGNORE INTO activity_meta(key, value) VALUES ('schema_version', '1')"
            )
            migrated = connection.execute(
                "SELECT value FROM activity_meta WHERE key = 'legacy_json_imported'"
            ).fetchone()
            if migrated is None:
                self._import_legacy_json(connection)
                connection.execute(
                    "INSERT INTO activity_meta(key, value) VALUES ('legacy_json_imported', '1')"
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._secure_database_files()

    def _import_legacy_json(self, connection: sqlite3.Connection) -> None:
        data = self._read_legacy_json()
        if data is None:
            return
        user_totals: dict[tuple[str, str], int] = {}
        for user_id, user_data in data["users"].items():
            username = user_data["username"]
            self._upsert_user(connection, user_id, username)
            for category, values in user_data["counters"].items():
                for counter, amount in values.items():
                    if amount <= 0:
                        continue
                    self._insert_sample(connection, 0, category, counter, amount, user_id)
                    key = (category, counter)
                    user_totals[key] = user_totals.get(key, 0) + amount
        for category, values in data["totals"].items():
            for counter, amount in values.items():
                residual = max(0, amount - user_totals.get((category, counter), 0))
                if residual:
                    self._insert_sample(connection, 0, category, counter, residual, "")
        for event in reversed(data["recent"]):
            connection.execute(
                """
                INSERT INTO activity_events
                    (recorded_at, category, title, detail, user_id, username)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    self._legacy_timestamp(event["timestamp"]),
                    event["category"],
                    event["title"],
                    event["detail"],
                    event["user_id"],
                    event["username"],
                ),
            )

    def _read_legacy_json(self) -> dict[str, Any] | None:
        if not self.legacy_path.exists():
            return None
        try:
            with self.legacy_path.open("r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if not isinstance(raw, dict):
                return None
            return self._normalize_legacy(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            return None

    def _normalize_legacy(self, data: dict[str, Any]) -> dict[str, Any]:
        totals = self._normalize_counters(data.get("totals", data.get("counters", {})))
        users: dict[str, Any] = {}
        raw_users = data.get("users", {})
        if isinstance(raw_users, dict):
            for user_id, user_data in raw_users.items():
                if not isinstance(user_data, dict):
                    continue
                raw_counters = user_data.get("counters", {})
                if not isinstance(raw_counters, dict):
                    continue
                users[str(user_id)] = {
                    "username": str(user_data.get("username", user_id)),
                    "counters": self._normalize_counters(raw_counters),
                }
        recent = []
        raw_recent = data.get("recent", [])
        if isinstance(raw_recent, list):
            recent = [
                {
                    "timestamp": str(item.get("timestamp", "")),
                    "category": str(item.get("category", "")),
                    "title": str(item.get("title", "")),
                    "detail": str(item.get("detail", "")),
                    "user_id": str(item.get("user_id", "")),
                    "username": str(item.get("username", "")),
                }
                for item in raw_recent[:20]
                if isinstance(item, dict)
            ]
        return {"totals": totals, "users": users, "recent": recent}

    def _aggregate_counters(
        self,
        connection: sqlite3.Connection,
        *,
        range_start: int | None,
        range_end: int | None,
        user_id: str | None = None,
    ) -> dict[str, dict[str, int]]:
        counters = self._normalize_counters({})
        conditions = []
        parameters: list[Any] = []
        if range_start is not None:
            conditions.append("recorded_at >= ?")
            parameters.append(range_start)
        if range_end is not None:
            conditions.append("recorded_at <= ?")
            parameters.append(range_end)
        if user_id is not None:
            conditions.append("user_id = ?")
            parameters.append(user_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = connection.execute(
            f"""
            SELECT category, counter, COALESCE(SUM(amount), 0) AS total
            FROM activity_samples
            {where}
            GROUP BY category, counter
            """,
            parameters,
        ).fetchall()
        for row in rows:
            counters.setdefault(row["category"], {})
            counters[row["category"]][row["counter"]] = int(row["total"])
        return counters

    def _aggregate_users(
        self,
        connection: sqlite3.Connection,
        *,
        range_start: int | None,
        range_end: int | None,
        selected_rank: dict[str, str],
    ) -> list[dict[str, Any]]:
        conditions = []
        parameters: list[Any] = []
        if range_start is not None:
            conditions.append("s.recorded_at >= ?")
            parameters.append(range_start)
        if range_end is not None:
            conditions.append("s.recorded_at <= ?")
            parameters.append(range_end)
        range_condition = (
            f"AND {' AND '.join(conditions)}" if conditions else ""
        )
        rows = connection.execute(
            f"""
            SELECT s.user_id, u.username
            FROM activity_samples AS s
            JOIN activity_users AS u ON u.user_id = s.user_id
            WHERE s.user_id != '' {range_condition}
            GROUP BY s.user_id, u.username
            """,
            tuple(parameters),
        ).fetchall()
        users = []
        for row in rows:
            counters = self._aggregate_counters(
                connection,
                range_start=range_start,
                range_end=range_end,
                user_id=row["user_id"],
            )
            if not self._has_activity(counters):
                continue
            users.append(
                {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "actions": self._counter_value(counters, "actions", "total"),
                    "counters": counters,
                    "metrics": self._scoreboard_metrics(counters),
                    "rank_value": self._counter_value(
                        counters, selected_rank["category"], selected_rank["counter"]
                    ),
                }
            )
        users.sort(
            key=lambda user: (
                -user["rank_value"],
                -user["actions"],
                user["username"].lower(),
            )
        )
        return users

    def _recent_events(
        self,
        connection: sqlite3.Connection,
        *,
        range_start: int | None,
        range_end: int | None,
    ) -> list[dict[str, str]]:
        conditions = []
        parameters: list[Any] = []
        if range_start is not None:
            conditions.append("recorded_at >= ?")
            parameters.append(range_start)
        if range_end is not None:
            conditions.append("recorded_at <= ?")
            parameters.append(range_end)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = connection.execute(
            f"""
            SELECT recorded_at, category, title, detail, user_id, username
            FROM activity_events
            {where}
            ORDER BY recorded_at DESC, id DESC
            LIMIT 20
            """,
            tuple(parameters),
        ).fetchall()
        return [
            {
                "timestamp": datetime.fromtimestamp(row["recorded_at"]).isoformat(
                    timespec="seconds"
                ),
                "category": row["category"],
                "title": row["title"],
                "detail": row["detail"],
                "user_id": row["user_id"],
                "username": row["username"],
            }
            for row in rows
        ]

    def _upsert_user(
        self, connection: sqlite3.Connection, user_id: str, username: str
    ) -> None:
        if not user_id:
            return
        connection.execute(
            """
            INSERT INTO activity_users(user_id, username) VALUES (?, ?)
            ON CONFLICT(user_id) DO UPDATE SET username = excluded.username
            """,
            (user_id, username or user_id),
        )

    def _insert_sample(
        self,
        connection: sqlite3.Connection,
        recorded_at: int,
        category: str,
        counter: str,
        amount: int,
        user_id: str,
    ) -> None:
        if amount == 0:
            return
        connection.execute(
            """
            INSERT INTO activity_samples
                (recorded_at, category, counter, amount, user_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (recorded_at, category, counter, amount, user_id),
        )

    def _normalize_counters(self, raw: Any) -> dict[str, dict[str, int]]:
        counters = {category: dict(values) for category, values in DEFAULT_COUNTERS.items()}
        if not isinstance(raw, dict):
            return counters
        for category, values in raw.items():
            if not isinstance(values, dict):
                continue
            counters.setdefault(str(category), {})
            for counter, value in values.items():
                amount = int(value)
                counters[str(category)][str(counter)] = max(0, amount)
        return counters

    def _dashboard_cards(
        self, counters: dict[str, dict[str, int]]
    ) -> list[dict[str, Any]]:
        cards = []
        for metric in METRIC_DEFINITIONS:
            values = dict(counters[metric.key])
            values.update(
                {
                    f"{counter}_display": self._format_counter(counter, value)
                    for counter, value in counters[metric.key].items()
                }
            )
            cards.append({
                "metric": metric.key,
                "kicker": metric.kicker,
                "title": metric.title,
                "primary": counters[metric.key][metric.primary_counter],
                "primary_label": metric.primary_label,
                "secondary": metric.secondary_template.format(**values),
            })
        return cards

    def _format_counter(self, counter: str, value: int) -> str:
        if not counter.endswith("bytes") and "bytes_" not in counter:
            return f"{value:,}"
        amount = float(value)
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if amount < 1024 or unit == "TiB":
                precision = 0 if unit == "B" or amount >= 100 else 1
                return f"{amount:.{precision}f} {unit}"
            amount /= 1024
        return f"{value:,} B"

    def _scoreboard_metrics(
        self, counters: dict[str, dict[str, int]]
    ) -> list[dict[str, Any]]:
        metrics = []
        for option in SCOREBOARD_RANKS[1:]:
            value = self._counter_value(counters, option["category"], option["counter"])
            if value > 0:
                metrics.append(
                    {
                        "key": option["key"],
                        "label": option["label"],
                        "value": value,
                        "unit": option["unit"],
                    }
                )
        return metrics

    def _window(self, key: str) -> dict[str, Any]:
        return next(
            (option for option in ACTIVITY_WINDOWS if option["key"] == key),
            next(option for option in ACTIVITY_WINDOWS if option["key"] == "lifetime"),
        )

    def _time_bounds(
        self,
        window: dict[str, Any],
        custom_start: str,
        custom_end: str,
    ) -> tuple[int | None, int | None, str]:
        if window["key"] == "custom":
            now = datetime.fromtimestamp(time.time()).replace(microsecond=0)
            default_start = now - timedelta(hours=1)
            try:
                start = (
                    datetime.fromisoformat(custom_start)
                    if custom_start
                    else default_start
                )
                end = datetime.fromisoformat(custom_end) if custom_end else now
                start_timestamp = int(start.timestamp())
                end_timestamp = int(end.timestamp())
                if start_timestamp > end_timestamp:
                    raise ValueError("start follows end")
                return start_timestamp, end_timestamp, ""
            except ValueError:
                return (
                    int(default_start.timestamp()),
                    int(now.timestamp()),
                    "Choose a valid start time that is before the end time.",
                )
        seconds = window["seconds"]
        start = int(time.time()) - int(seconds) if seconds is not None else None
        return start, None, ""

    def _datetime_input_value(self, timestamp: int | None) -> str:
        if timestamp is None:
            return ""
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%dT%H:%M:%S")

    def _range_label(
        self,
        window: dict[str, Any],
        range_start: int | None,
        range_end: int | None,
    ) -> str:
        if window["key"] != "custom" or range_start is None or range_end is None:
            return str(window["label"])
        start = datetime.fromtimestamp(range_start).strftime("%b %d, %Y %I:%M %p")
        end = datetime.fromtimestamp(range_end).strftime("%b %d, %Y %I:%M %p")
        return f"{start} – {end}"

    def _counter_value(
        self, counters: dict[str, dict[str, int]], category: str, counter: str
    ) -> int:
        return int(counters.get(category, {}).get(counter, 0))

    def _has_activity(self, counters: dict[str, dict[str, int]]) -> bool:
        return any(
            int(value) > 0
            for category in counters.values()
            for value in category.values()
        )

    def _validate_amount(self, amount: int) -> None:
        if not isinstance(amount, int) or amount < 0:
            raise ValueError("Activity counter increments must be positive.")

    def _legacy_timestamp(self, value: str) -> int:
        try:
            return int(datetime.fromisoformat(value).timestamp())
        except (TypeError, ValueError):
            return 0

    def _secure_database_files(self) -> None:
        for candidate in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
        ):
            if candidate.exists():
                os.chmod(candidate, 0o600)
