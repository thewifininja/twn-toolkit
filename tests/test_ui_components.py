from __future__ import annotations

import unittest
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "twn_toolkit" / "templates"


class UIComponentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = Environment(
            loader=FileSystemLoader(TEMPLATE_ROOT),
            autoescape=select_autoescape(("html", "xml")),
        )

    def render(self, source: str) -> str:
        return self.environment.from_string(source).render()

    def test_shared_page_shell_uses_wide_responsive_content_cap(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("--page-content-max-width: 1600px;", stylesheet)
        self.assertIn(".shell > * {", stylesheet)
        self.assertIn("max-width: var(--page-content-max-width);", stylesheet)

    def test_workspace_section_and_empty_state_contracts(self) -> None:
        html = self.render(
            """
            {% from "components/ui.html" import empty_state, section_header, workspace_intro %}
            {{ workspace_intro("Profiles", "Reusable connections", "Workspace") }}
            {% call section_header("Servers", "Saved endpoints", class_name="profile-manager-head") %}
              <button>New server</button>
            {% endcall %}
            {{ empty_state("No servers", "Create the first server.") }}
            """
        )

        self.assertIn('class="workspace-intro"', html)
        self.assertIn('<span class="eyebrow">Workspace</span>', html)
        self.assertIn('class="section-head has-actions profile-manager-head"', html)
        self.assertIn('class="section-actions"', html)
        self.assertIn('class="empty-state"', html)

    def test_host_range_guidance_documents_shared_syntax_and_expanded_limit(self) -> None:
        html = self.render(
            """
            {% from "components/ui.html" import host_range_guidance %}
            {{ host_range_guidance(50, "hosts") }}
            """
        )

        self.assertIn("inclusive IP range", html)
        self.assertIn("<code>Name = target</code>", html)
        self.assertIn("<code>Name-0001</code>", html)
        self.assertIn("Maximum 50 hosts after expansion", html)

    def test_profile_and_action_component_contracts(self) -> None:
        html = self.render(
            """
            {% from "components/ui.html" import action_row, profile_card, profile_create, profile_section %}
            {% call profile_section("Credentials", "2 saved", open=true) %}
              {% call profile_create("New credential") %}<form></form>{% endcall %}
              {% call profile_card("Operator", "operator@example.test", open=true) %}
                {% call action_row(detached=true) %}<button>Update</button><button>Delete</button>{% endcall %}
              {% endcall %}
            {% endcall %}
            """
        )

        self.assertIn('class="access-profile-card profile-section" open', html)
        self.assertIn('class="profile-create-details card-action-details"', html)
        self.assertIn('class="card-action-closed-label">New credential</span>', html)
        self.assertIn('class="card-action-open-label">Cancel</span>', html)
        self.assertIn('class="access-profile-card nested-profile-card" open', html)
        self.assertIn('class="button-row profile-form-actions"', html)

    def test_profile_create_surface_uses_shared_collection_token(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("--profile-collection-surface:", stylesheet)
        self.assertIn(
            ".profile-section > .profile-create-details.card-action-details[open] {",
            stylesheet,
        )
        self.assertIn("background: var(--profile-collection-surface);", stylesheet)

    def test_shared_action_palette_separates_primary_and_destructive_actions(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("--action-primary: #2f7656;", stylesheet)
        self.assertIn("--action-primary: #357f5d;", stylesheet)
        self.assertIn("background: var(--action-primary);", stylesheet)
        self.assertIn("background: var(--action-primary-hover);", stylesheet)
        self.assertIn("background: var(--action-danger);", stylesheet)

    def test_dashboard_metric_values_stay_within_their_cards(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn(".dashboard-stat {", stylesheet)
        self.assertIn("flex-wrap: wrap;", stylesheet)
        self.assertIn("font-variant-numeric: tabular-nums;", stylesheet)
        self.assertIn("white-space: nowrap;", stylesheet)
        dashboard_stat_rule = stylesheet.split(".dashboard-stat span {", 1)[1].split(
            "}", 1
        )[0]
        self.assertNotIn("overflow-wrap: anywhere;", dashboard_stat_rule)

    def test_dashboard_quick_launch_favorite_is_vertically_centered(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        favorite_form_rule = stylesheet.split(".workspace-tool-card form {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("top: 50%;", favorite_form_rule)
        self.assertIn("transform: translateY(-50%);", favorite_form_rule)
        self.assertNotIn("top: 8px;", favorite_form_rule)

    def test_sidebar_favorite_star_and_drag_handle_are_centered(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        favorite_button_rule = stylesheet.split(".side-nav-favorite-button {", 1)[
            1
        ].split("}", 1)[0]
        self.assertIn("align-items: center;", favorite_button_rule)
        self.assertIn(".side-nav-favorite-star {", stylesheet)
        self.assertIn(".side-nav-favorite-drag-handle {", stylesheet)
        self.assertIn("grid-template-columns: 24px minmax(0, 1fr);", stylesheet)

    def test_automation_threshold_rows_share_aligned_label_space(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        condition_template = (
            TEMPLATE_ROOT / "automations" / "_condition_forms.html"
        ).read_text(encoding="utf-8")

        self.assertIn(".automation-threshold-grid > label {", stylesheet)
        self.assertIn("grid-template-rows: minmax(2.35em, auto) auto;", stylesheet)
        self.assertGreaterEqual(condition_template.count("automation-threshold-grid"), 5)

    def test_ping_results_use_a_responsive_master_detail_workspace(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        script = (
            TEMPLATE_ROOT.parent / "static" / "ping-tool.js"
        ).read_text(encoding="utf-8")

        self.assertIn(".ping-results-workspace {", stylesheet)
        self.assertIn("grid-template-columns: minmax(250px, 320px) minmax(0, 1fr);", stylesheet)
        self.assertIn('.ping-host-option[data-state="up"] .ping-host-state-dot {', stylesheet)
        self.assertIn('.ping-host-option[data-state="down"] .ping-host-state-dot {', stylesheet)
        self.assertIn(".ping-graph-card {", stylesheet)
        self.assertIn(".ping-host-statistics .ping-statistics span {", stylesheet)
        self.assertIn("display: inline-flex;", stylesheet)
        self.assertIn(
            "grid-template-columns: fit-content(28%) minmax(300px, 1fr) auto;",
            stylesheet,
        )
        self.assertIn("white-space: nowrap;", stylesheet)
        self.assertIn('["Now", current?.reachable', script)
        self.assertIn("header.append(identity, statistics, actions);", script)
        self.assertIn("card.append(header, chart);", script)
        self.assertIn(
            'remove.className = "graph-close-button ping-graph-remove";',
            script,
        )
        self.assertIn('remove.setAttribute("aria-label", removeLabel);', script)
        self.assertIn(".graph-close-button::before,", stylesheet)
        self.assertIn("transform: translate(-50%, -50%) rotate(45deg);", stylesheet)
        self.assertIn(".graph-close-button:hover,", stylesheet)
        self.assertIn("@media (max-width: 1050px) {", stylesheet)
        self.assertIn("grid-template-rows: auto auto auto minmax(0, 1fr) auto;", stylesheet)
        self.assertIn("overflow-y: auto;", stylesheet)
        self.assertIn("scrollbar-gutter: stable;", stylesheet)

    def test_live_tools_use_a_low_profile_footer_dock(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        script = (
            TEMPLATE_ROOT.parent / "static" / "live-tools.js"
        ).read_text(encoding="utf-8")

        self.assertIn("--live-tool-dock-height: 42px;", stylesheet)
        self.assertIn("bottom: calc(100% + 8px);", stylesheet)
        self.assertIn("left: 300px;", stylesheet)
        self.assertIn(".sidebar-collapsed .live-tool-tray {", stylesheet)
        self.assertIn('id="live-tool-dock-summary"', template)
        self.assertIn("setExpanded(false);", script)
        self.assertNotIn("localStorage", script)
        self.assertIn("collapse: () => setExpanded(false)", script)
        self.assertIn('iconButton("✎"', script)
        self.assertIn('save.type = "submit";', script)
        self.assertIn('restore.className = "live-tool-card-restore";', script)
        self.assertIn('iconButton("×", `Stop ${title.textContent}`', script)
        self.assertIn('restore.setAttribute("aria-label"', script)
        self.assertNotIn('iconSymbol("▶")', script)
        self.assertIn(".live-tool-card .live-tool-rename {", stylesheet)
        self.assertIn(".live-tool-card .live-tool-icon-action {", stylesheet)
        self.assertIn(".live-tool-card-restore {", stylesheet)
        self.assertIn("inset: 0;", stylesheet)

    def test_live_ping_page_refreshes_samples_subsecond_while_visible(self) -> None:
        script = (
            TEMPLATE_ROOT.parent / "static" / "ping-tool.js"
        ).read_text(encoding="utf-8")

        self.assertIn("const visiblePollIntervalMs = 250;", script)
        self.assertIn("const hiddenPollIntervalMs = 5_000;", script)
        self.assertIn(
            "document.hidden ? hiddenPollIntervalMs : visiblePollIntervalMs",
            script,
        )
        self.assertNotIn("setTimeout(pollSession, 2_000)", script)
        self.assertNotIn("fetch(activeSession.detail_url", script)
        self.assertIn("if (data.session) activeSession = data.session;", script)

    def test_live_ping_graph_selection_persists_for_each_session(self) -> None:
        script = (
            TEMPLATE_ROOT.parent / "static" / "ping-tool.js"
        ).read_text(encoding="utf-8")

        self.assertIn('const graphSelectionStoragePrefix = "twn:ping-graphs:";', script)
        self.assertIn("restoreGraphSelection();", script)
        self.assertIn("persistGraphSelection();", script)
        self.assertIn(
            "if (selectedHosts.has(result.host) && !graphViews.has(result.host))",
            script,
        )
        self.assertIn("selectGraph(result.host, {persist: false});", script)
        self.assertIn(
            "sessionStorage.setItem(storageKey, JSON.stringify(hosts));",
            script,
        )

    def test_snmp_monitor_restores_from_persistent_live_tool_samples(self) -> None:
        template = (
            TEMPLATE_ROOT / "tools" / "snmp_test.html"
        ).read_text(encoding="utf-8")
        script = (
            TEMPLATE_ROOT.parent / "static" / "snmp-interface-monitor.js"
        ).read_text(encoding="utf-8")

        self.assertIn('data-requested-session="{{ requested_live_session }}"', template)
        self.assertIn("snmp-monitor-minimize", template)
        self.assertIn("activeSession.samples_url", script)
        self.assertIn("restoreSession(root.dataset.requestedSession)", script)
        self.assertIn("window.TwnLiveTools?.refresh()", script)
        self.assertNotIn('window.addEventListener("pagehide"', script)
        self.assertIn("const visiblePollIntervalMs = 250;", script)
        self.assertIn("const hiddenPollIntervalMs = 5_000;", script)
        self.assertNotIn("getJson(activeSession.detail_url", script)
        self.assertIn("activeSession = page.session;", script)
        self.assertIn(
            'remove.className = "graph-close-button snmp-monitor-remove";',
            script,
        )
        self.assertIn('remove.setAttribute("aria-label", removeLabel);', script)

    def test_port_scanner_profile_columns_share_aligned_rows(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "tools" / "port_scanner.html").read_text(
            encoding="utf-8"
        )

        self.assertIn('class="grid two port-profile-grid"', template)
        self.assertEqual(template.count("button-row port-profile-actions"), 2)
        self.assertIn("grid-template-rows: auto auto minmax(3.6em, auto) auto;", stylesheet)
        self.assertIn("grid-template-columns: minmax(0, 1fr) auto auto;", stylesheet)

    def test_dns_workspace_aligns_inputs_and_bounds_load_testing(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "tools" / "dns_response.html").read_text(
            encoding="utf-8"
        )

        self.assertEqual(template.count('class="dns-input-card"'), 2)
        self.assertIn('class="dns-input-grid"', template)
        self.assertIn("data-dns-load-only", template)
        self.assertIn('name="authorized"', template)
        self.assertIn("I am authorized to load test these DNS servers", template)
        self.assertIn(".dns-input-card {", stylesheet)
        self.assertIn(
            "grid-template-rows: auto auto minmax(0, 1fr) minmax(68px, auto) auto;",
            stylesheet,
        )

    def test_iperf_workspace_has_client_and_managed_server_history(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "tools" / "iperf3.html").read_text(
            encoding="utf-8"
        )

        self.assertEqual(template.count('class="iperf-action-card'), 2)
        self.assertIn('name="client_authorized"', template)
        self.assertIn('name="server_authorized"', template)
        self.assertIn("Start server", template)
        self.assertIn("Stop server", template)
        self.assertIn("appears in Live tools and on the dashboard", template)
        self.assertIn("busy bind address or port is rejected", template)
        self.assertIn("Server test history", template)
        self.assertIn("data-iperf-server-started", template)
        self.assertIn('data-iperf-server-results', template)
        self.assertIn("The toolkit never installs", template)
        self.assertIn(".iperf-action-grid {", stylesheet)
        self.assertIn(".iperf-server-result-card {", stylesheet)
        self.assertIn(
            "grid-template-columns: repeat(2, minmax(0, 1fr));",
            stylesheet,
        )

    def test_multicast_workspace_exposes_bounded_modes_and_reports(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "tools" / "multicast.html").read_text(
            encoding="utf-8"
        )

        self.assertEqual(template.count('class="multicast-mode-card"'), 3)
        self.assertIn('value="listen"', template)
        self.assertIn('value="send"', template)
        self.assertIn('value="path"', template)
        self.assertIn('name="authorized"', template)
        self.assertIn("Source-specific multicast (SSM)", template)
        self.assertIn("RTP version 2", template)
        self.assertIn("mDNS · 224.0.0.251:5353", template)
        self.assertIn("multicast-live-panel", template)
        self.assertIn("multicast-live-timeline", template)
        self.assertIn("multicast-cancel", template)
        self.assertIn("Download JSON", template)
        self.assertIn("one million packets per run", template)
        self.assertIn(".multicast-mode-picker {", stylesheet)
        script = (TEMPLATE_ROOT.parent / "static" / "multicast.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('mode === "path"', script)
        self.assertIn("receiveInterface.options", script)
        self.assertIn("response.body.getReader()", script)
        self.assertIn("handleProgress", script)
        self.assertIn("activeController?.abort()", script)


if __name__ == "__main__":
    unittest.main()
