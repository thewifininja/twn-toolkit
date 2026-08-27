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

    def test_shared_page_shell_uses_full_responsive_content_width(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("--page-inline-gutter: clamp(14px, 2vw, 28px);", stylesheet)
        self.assertIn(".shell > * {", stylesheet)
        self.assertIn("padding: 24px var(--page-inline-gutter);", stylesheet)
        self.assertIn("max-width: none;", stylesheet)
        self.assertIn("width: 100%;", stylesheet)

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

    def test_shared_workspace_header_and_tabs_contracts(self) -> None:
        html = self.render(
            """
            {% from "components/ui.html" import workspace_chrome %}
            {{ workspace_chrome(
              "Automation",
              "Build reliable workflows.",
              "Workspace",
              [
                {"label": "Automations", "href": "/automations", "active": true},
                {"label": "Actions", "href": "/automations/actions", "active": false}
              ],
              "Automation sections",
              "Configured",
              "12",
              "Reusable records"
            ) }}
            """
        )

        self.assertIn('class="workspace-header has-metric"', html)
        self.assertIn('class="workspace-header-metric"', html)
        self.assertIn('class="workspace-tabs" aria-label="Automation sections"', html)
        self.assertIn('class="workspace-tab is-active"', html)
        self.assertIn('aria-current="page"', html)
        self.assertLess(html.index('class="workspace-tabs"'), html.index('class="workspace-header'))

    def test_shared_workspace_shell_is_responsive(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn(".workspace-page {", stylesheet)
        self.assertIn(".workspace-header.has-metric {", stylesheet)
        self.assertIn(".workspace-tabs {", stylesheet)
        self.assertIn(".workspace-tab.is-active {", stylesheet)
        self.assertIn("--workspace-section-gap: 18px;", stylesheet)
        self.assertIn("gap: var(--workspace-section-gap);", stylesheet)
        self.assertIn(".shell > * + * {", stylesheet)

    def test_case_recorded_notice_preserves_shell_centering(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        notice_rule = stylesheet.split(
            ".investigation-recorded-notice {", 1
        )[1].split("}", 1)[0]

        self.assertIn("margin: 14px auto;", notice_rule)

    def test_active_case_banner_has_a_responsive_quick_note_dialog(self) -> None:
        template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        script = (TEMPLATE_ROOT.parent / "static" / "case-note.js").read_text(
            encoding="utf-8"
        )

        self.assertIn("data-case-note-open", template)
        self.assertIn("data-case-note-dialog", template)
        self.assertEqual(template.count("active-investigation-action"), 4)
        self.assertEqual(
            template.count('class="secondary active-investigation-action"'), 2
        )
        self.assertIn(
            'class="button-link secondary active-investigation-action"', template
        )
        self.assertIn('name="next" value="{{ request.full_path }}"', template)
        self.assertIn(".active-case-note-dialog {", stylesheet)
        self.assertIn("max-width: calc(100vw - 32px);", stylesheet)
        self.assertIn("flex-wrap: wrap;", stylesheet)
        action_rule = stylesheet.split(
            ".active-investigation-actions .active-investigation-action {", 1
        )[1].split("}", 1)[0]
        self.assertIn("min-height: 34px;", action_rule)
        self.assertNotIn("background:", action_rule)
        self.assertNotIn("border:", action_rule)
        self.assertIn("dialog.showModal()", script)
        self.assertIn("note.focus()", script)

    def test_active_case_and_remote_terminal_share_the_full_workspace_width(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        remote_template = (
            TEMPLATE_ROOT / "tools" / "remote_terminal.html"
        ).read_text(encoding="utf-8")
        remote_connections = (
            TEMPLATE_ROOT.parent / "static" / "remote-connections.js"
        ).read_text(encoding="utf-8")

        case_banner_rule = stylesheet.split(
            ".active-investigation-banner {", 1
        )[1].split("}", 1)[0]
        terminal_manager_rule = stylesheet.split(
            ".remote-terminal-manager {", 1
        )[1].split("}", 1)[0]
        library_actions_rule = stylesheet.split(
            ".remote-connection-library-actions {", 1
        )[1].split("}", 1)[0]

        for rule in (case_banner_rule, terminal_manager_rule):
            self.assertIn("max-width: none;", rule)
            self.assertIn("width: 100%;", rule)
        self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr));", library_actions_rule)
        self.assertIn("const minimumLibraryWidth = 330;", remote_connections)
        self.assertIn(
            'class="remote-connection-library-actions"',
            remote_template,
        )
        self.assertIn(
            'class="secondary compact" type="button" data-open-credentials>Credentials',
            remote_template,
        )
        self.assertNotIn(".remote-connection-explorer > footer {", stylesheet)

    def test_remote_terminal_launchers_and_dialogs_have_clear_roles(self) -> None:
        remote_template = (
            TEMPLATE_ROOT / "tools" / "remote_terminal.html"
        ).read_text(encoding="utf-8")
        remote_script = (
            TEMPLATE_ROOT.parent / "static" / "remote-connections.js"
        ).read_text(encoding="utf-8")
        terminal_workspace = (
            TEMPLATE_ROOT / "tools" / "_remote_terminal_workspace.html"
        ).read_text(encoding="utf-8")

        self.assertNotIn(">New session</button>", remote_template)
        self.assertIn(">Quick connect</button>", remote_template)
        self.assertIn('id="remote-terminal-new-session"', remote_template)
        terminal_script = (
            TEMPLATE_ROOT.parent / "static" / "remote-terminal.js"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "newSessionButton.hidden = !activeSessions.length", terminal_script
        )
        self.assertIn('class="remote-terminal-dialog-section"', remote_template)
        self.assertIn('class="remote-terminal-advanced-options"', remote_template)
        self.assertIn('id="remote-credential-editor-title"', remote_template)
        self.assertIn('id="remote-credential-count"', remote_template)
        self.assertIn('id="remote-credential-save"', remote_template)
        self.assertIn('openDialog(quickDialog, "remote-terminal-host")', remote_script)
        self.assertIn('credential ? "Edit credential" : "New credential"', remote_script)
        self.assertIn('setAttribute("aria-haspopup", "menu")', remote_script)
        self.assertIn('setAttribute("role", "menuitem")', remote_script)
        self.assertIn('event.key !== "Escape"', remote_script)
        self.assertNotIn("remote-connection-folder-tools", remote_script)
        self.assertIn('id="remote-terminal-session-rename"', terminal_workspace)
        self.assertIn('id="remote-terminal-rename-dialog"', terminal_workspace)
        self.assertIn("saved host name stays unchanged", terminal_workspace)

    def test_remote_terminal_tabs_can_be_renamed_and_closed(self) -> None:
        script = (TEMPLATE_ROOT.parent / "static" / "remote-terminal.js").read_text(
            encoding="utf-8"
        )
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn('tabAction("✎", `Rename ${session.title}`', script)
        self.assertIn('tabAction("×", `Close ${session.title}`', script)
        self.assertIn("async function closeSessionTab(session, control)", script)
        self.assertIn("scrollback will remain in Recent sessions", script)
        self.assertIn("async function saveSessionName(event)", script)
        self.assertIn("fetch(session.rename_url", script)
        self.assertIn(".remote-terminal-tab-shell {", stylesheet)
        self.assertIn(".remote-terminal-tab-action.close:hover", stylesheet)

    def test_remote_terminal_reconnects_from_checkpoint_without_losing_history(self) -> None:
        script = (TEMPLATE_ROOT.parent / "static" / "remote-terminal.js").read_text(
            encoding="utf-8"
        )
        emulator = (
            TEMPLATE_ROOT.parent / "static" / "terminal-emulator.js"
        ).read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("async function persistCheckpoint()", script)
        self.assertIn('bootstrap ? "&bootstrap=1"', script)
        self.assertIn('focusState.textContent = "Restoring session…"', script)
        self.assertIn("data.chunks.map((chunk) => chunk.output).join", script)
        self.assertIn("serialize(options = {}) {", emulator)
        self.assertIn("restore(snapshot) {", emulator)
        self.assertGreaterEqual(stylesheet.count("overflow-anchor: none;"), 2)

    def test_remote_terminal_keeps_focus_and_exposes_live_follow_controls(self) -> None:
        workspace = (
            TEMPLATE_ROOT / "tools" / "_remote_terminal_workspace.html"
        ).read_text(encoding="utf-8")
        script = (TEMPLATE_ROOT.parent / "static" / "remote-terminal.js").read_text(
            encoding="utf-8"
        )
        emulator = (
            TEMPLATE_ROOT.parent / "static" / "terminal-emulator.js"
        ).read_text(encoding="utf-8")

        self.assertIn('id="remote-terminal-jump-live"', workspace)
        self.assertIn('class="remote-terminal-surface-bar"', workspace)
        self.assertGreater(
            workspace.index('class="remote-terminal-surface-bar"'),
            workspace.index('id="remote-terminal-surface"'),
        )
        self.assertIn("jumpToLive({focus: false})", script)
        self.assertIn("inputCapture.disabled !== inputDisabled", script)
        self.assertIn("synchronizing = wasSynchronizing && pollImmediately", script)
        self.assertNotIn("synchronizing = pollImmediately;", script)
        self.assertIn("New output · Jump to live", script)
        self.assertIn("options.historyLimit", emulator)
        self.assertIn("renderOverscan", emulator)
        self.assertIn("scrollToBottom()", emulator)

    def test_remote_terminal_exposes_case_and_datastore_capture_actions(self) -> None:
        workspace = (
            TEMPLATE_ROOT / "tools" / "_remote_terminal_workspace.html"
        ).read_text(encoding="utf-8")
        script = (TEMPLATE_ROOT.parent / "static" / "remote-terminal.js").read_text(
            encoding="utf-8"
        )
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn('data-active-case-id="{{ active_investigation.id', workspace)
        self.assertIn('id="remote-terminal-attach-case"', workspace)
        self.assertIn('id="remote-terminal-save-datastore"', workspace)
        self.assertIn('id="remote-terminal-transcript-view"', workspace)
        self.assertIn('id="remote-terminal-datastore-dialog"', workspace)
        self.assertIn("all retained scrollback, including output produced before attachment", script)
        self.assertIn("This saves the output retained so far as a snapshot", script)
        self.assertIn('terminalActionIcon("datastore")', script)
        self.assertIn('terminalActionIcon("case")', script)
        self.assertIn(".remote-terminal-case-pill {", stylesheet)
        self.assertIn(".remote-terminal-datastore-dialog {", stylesheet)

    def test_remote_host_action_stays_a_compact_square(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        rule = stylesheet.rsplit(
            ".remote-connection-host-manage {", 1
        )[1].split("}", 1)[0]

        self.assertIn("align-self: center;", rule)
        self.assertIn("height: 30px;", rule)
        self.assertIn("min-height: 30px;", rule)
        self.assertIn("width: 30px;", rule)
        self.assertIn("padding: 0;", rule)

    def test_every_peer_view_uses_shared_tabs_first_workspace_structure(self) -> None:
        shared_chrome_templates = (
            "automations/index.html",
            "auth/settings.html",
            "auth/updates.html",
            "auth/backup.html",
            "investigations/detail.html",
        )

        for template_name in shared_chrome_templates:
            template = (TEMPLATE_ROOT / template_name).read_text(encoding="utf-8")
            with self.subTest(template=template_name):
                self.assertIn("workspace_chrome(", template)

        certificate_template = (
            TEMPLATE_ROOT / "tools" / "certificate_automation.html"
        ).read_text(encoding="utf-8")
        self.assertIn('class="workspace-page certificate-workspace"', certificate_template)
        self.assertLess(
            certificate_template.index("workspace_tabs('Certificate authority'"),
            certificate_template.index('class="panel tool-panel certificate-automation-hero"'),
        )

        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".admin-page-nav", stylesheet)
        self.assertNotIn(".automation-page-nav", stylesheet)

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

        self.assertIn('class="access-profile-card profile-section saved-profile-collection" open', html)
        self.assertIn('class="profile-create-details card-action-details saved-profile-create"', html)
        self.assertIn('class="card-action-closed-label">New credential</span>', html)
        self.assertIn('class="card-action-open-label">Cancel</span>', html)
        self.assertIn('class="access-profile-card nested-profile-card saved-profile-record" open', html)
        self.assertIn('class="button-row profile-form-actions saved-profile-record-actions"', html)

    def test_compact_saved_profile_manager_contract(self) -> None:
        html = self.render(
            """
            {% from "components/ui.html" import saved_profile_manager %}
            {% call saved_profile_manager("Target profiles", "Reusable host lists", 3, "tool-profile-manager") %}
              <select data-saved-profile-select><option>Branch</option></select>
            {% endcall %}
            """
        )

        self.assertIn('class="saved-profile-manager tool-profile-manager"', html)
        self.assertIn('data-saved-profile-manager', html)
        self.assertIn('class="saved-profile-kicker">Saved configuration</span>', html)
        self.assertIn('class="saved-profile-count">3 saved</span>', html)
        self.assertIn("Reusable host lists", html)

    def test_saved_profile_manager_state_contract(self) -> None:
        script = (TEMPLATE_ROOT.parent / "static" / "saved-profile-manager.js").read_text(
            encoding="utf-8"
        )
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn('manager.dataset.profileState = isRenaming ? "renaming"', script)
        self.assertIn('hasSavedProfile ? "Save changes" : "Save profile"', script)
        self.assertIn("duplicate.disabled = !hasSavedProfile", script)
        self.assertIn("remove.disabled = !hasSavedProfile", script)
        self.assertIn(".saved-profile-manager {", stylesheet)
        self.assertIn(".saved-profile-create.card-action-details:not([open])", stylesheet)
        self.assertIn("@container saved-profile-manager (max-width: 650px)", stylesheet)

    def test_data_dense_network_tools_can_use_the_full_content_width(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        tool_panel_rule = stylesheet.split(".tool-panel {", 1)[1].split("}", 1)[0]
        dns_panel_rule = stylesheet.split(".dns-workspace-panel,", 1)[1].split("}", 1)[0]
        traceroute_path_rule = stylesheet.split(".traceroute-path {", 1)[1].split(
            "}", 1
        )[0]

        self.assertIn("max-width: none;", tool_panel_rule)
        self.assertIn("max-width: none;", dns_panel_rule)
        self.assertIn("max-width: none;", traceroute_path_rule)

    def test_all_tool_workflow_entry_panels_use_the_full_content_width(self) -> None:
        workflow_templates = (
            "task.html",
            "fortiap_client_history.html",
            "fortiauthenticator/mac_devices.html",
            "fortiauthenticator/mac_group_memberships.html",
            "fortiauthenticator/mac_cleanup.html",
        )

        for template_name in workflow_templates:
            template = (TEMPLATE_ROOT / template_name).read_text(encoding="utf-8")
            with self.subTest(template=template_name):
                self.assertIn('<section class="panel tool-panel">', template)
                self.assertNotIn('class="panel narrow"', template)

    def test_legacy_tool_and_result_width_caps_are_removed(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertNotIn(".panel.narrow {", stylesheet)
        self.assertNotIn(".speed-test-panel {\n  max-width:", stylesheet)
        self.assertNotIn(".speed-test-notes {\n  max-width:", stylesheet)
        self.assertNotIn(".ip-address-panel {\n  max-width:", stylesheet)
        self.assertNotIn(".switch-order-tool {\n  max-width:", stylesheet)
        self.assertNotIn(".remote-terminal-popout-shell {\n  max-width:", stylesheet)
        for selector in (".preview-panel {", ".rename-editor {"):
            rule = stylesheet.split(selector, 1)[1].split("}", 1)[0]
            self.assertIn("max-width: none;", rule)

    def test_mobile_workspace_navigation_and_compact_profile_actions_do_not_clip(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        mobile_workspace = stylesheet.split("@media (max-width: 700px) {", 1)[1]
        self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr));", mobile_workspace)
        self.assertIn(".workspace-tab:last-child:nth-child(odd)", mobile_workspace)
        self.assertIn("main .link-button.subtle", mobile_workspace)
        self.assertIn("min-height: 32px;", mobile_workspace)

        compact_profiles = stylesheet.split(
            "@container saved-profile-manager (max-width: 300px) {", 1
        )[1].split("}", 1)[0]
        self.assertIn("grid-template-columns: minmax(0, 1fr);", compact_profiles)

    def test_investigation_evidence_and_reports_contain_dense_mobile_content(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            ".investigation-evidence-library .section-head p {", stylesheet
        )
        self.assertIn("overflow-wrap: anywhere;", stylesheet)
        self.assertIn(".investigation-report > *", stylesheet)
        self.assertIn(".investigation-report .table-wrap {", stylesheet)
        report_table_rule = stylesheet.split(
            ".investigation-report .table-wrap {", 1
        )[1].split("}", 1)[0]
        self.assertIn("max-width: 100%;", report_table_rule)
        self.assertIn("width: 100%;", report_table_rule)

    def test_investigation_start_form_and_detail_return_navigation_contract(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        index_template = (TEMPLATE_ROOT / "investigations" / "index.html").read_text(
            encoding="utf-8"
        )
        detail_template = (
            TEMPLATE_ROOT / "investigations" / "detail.html"
        ).read_text(encoding="utf-8")

        start_form_rule = stylesheet.split(
            ".form-grid.investigation-create-form {", 1
        )[1].split("}", 1)[0]
        self.assertIn("grid-template-columns: minmax(0, 1fr);", start_form_rule)
        self.assertIn('class="investigation-create-fields"', index_template)
        self.assertIn('class="investigation-create-actions"', index_template)
        self.assertIn("Start a case", index_template)
        self.assertIn("Open case", index_template)
        self.assertIn('class="investigation-return-nav"', detail_template)
        self.assertIn("Back to investigations", detail_template)
        self.assertIn("Reopen case", detail_template)
        self.assertIn('class="investigation-reopen-action"', detail_template)
        self.assertIn(
            ".investigation-overview-strip {\n  align-items: stretch;",
            stylesheet,
        )
        report_checkbox_rule = stylesheet.split(
            '.investigation-report-choice input[type="checkbox"] {', 1
        )[1].split("}", 1)[0]
        self.assertIn("appearance: none;", report_checkbox_rule)
        self.assertIn("min-height: 1.15rem;", report_checkbox_rule)
        self.assertIn("padding: 0;", report_checkbox_rule)

    def test_investigation_print_layout_allows_large_results_to_paginate(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        detail_template = (
            TEMPLATE_ROOT / "investigations" / "detail.html"
        ).read_text(encoding="utf-8")
        print_rules = stylesheet.split("@media print {", 1)[1].split(
            "\n\n.certificate-options", 1
        )[0]

        self.assertIn('class="investigation-report-evidence"', detail_template)
        self.assertIn('class="investigation-result-table"', detail_template)
        self.assertIn('class="panel investigation-report-builder"', detail_template)
        self.assertIn('href="#report-result-{{ event.id }}"', detail_template)
        self.assertIn('class="investigation-report-result"', detail_template)
        self.assertIn("download_investigation_package", detail_template)
        self.assertIn("download_investigation_report_pdf", detail_template)
        self.assertIn("display: block;", print_rules)
        self.assertIn(".investigation-report-builder", print_rules)
        self.assertIn(".investigation-report-evidence", print_rules)
        self.assertIn(".investigation-report-result", print_rules)
        self.assertIn("break-before: page;", print_rules)
        self.assertIn(".investigation-report table", print_rules)
        self.assertIn("break-inside: auto;", print_rules)
        self.assertIn(".investigation-report tr", print_rules)
        self.assertIn("display: table-header-group;", print_rules)
        self.assertIn(".investigation-report-event > header > div", print_rules)
        self.assertIn("padding: 4px 0 5px 9px;", print_rules)
        self.assertIn("font-size: 8.3pt;", print_rules)
        self.assertIn(
            "scroll-margin-top: calc(var(--topbar-height) + 16px);",
            stylesheet,
        )

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

    def test_sidebar_footer_survives_mobile_browser_chrome_and_desktop_is_compact(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        sidebar_script = (
            TEMPLATE_ROOT.parent / "static" / "sidebar.js"
        ).read_text(encoding="utf-8")

        self.assertIn("align-content: start;", stylesheet)
        self.assertIn("flex: 1 1 0;", stylesheet)
        self.assertIn("overscroll-behavior: contain;", stylesheet)
        self.assertIn("scrollbar-gutter: stable;", stylesheet)
        self.assertIn(
            "@media (min-width: 901px) and (hover: hover) and (pointer: fine) {",
            stylesheet,
        )
        self.assertIn(
            "@media (max-width: 900px), (hover: none) and (pointer: coarse) {",
            stylesheet,
        )
        self.assertIn(
            "var(--mobile-visual-viewport-height, 100dvh)",
            stylesheet,
        )
        self.assertIn(
            "window.visualViewport?.height || window.innerHeight",
            sidebar_script,
        )
        self.assertIn(
            'window.visualViewport?.addEventListener("resize", updateSidebarGeometry);',
            sidebar_script,
        )
        self.assertIn(
            '"(min-width: 901px) and (hover: hover) and (pointer: fine)"',
            sidebar_script,
        )
        self.assertIn("env(safe-area-inset-bottom)", stylesheet)
        self.assertIn("overflow-wrap: anywhere;", stylesheet)
        self.assertIn("Help &amp; release notes", template)
        self.assertIn("filename='sidebar.js', v=asset_version", template)

    def test_sidebar_nested_tools_are_text_only_and_keep_hierarchy_indent(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")

        self.assertIn('<ul class="side-nav-tool-list">', template)
        self.assertIn(
            ".side-nav-tool-list,\n.side-nav-tree {",
            stylesheet,
        )
        self.assertIn("margin-left: 12px !important;", stylesheet)
        self.assertIn("padding-left: 8px !important;", stylesheet)
        self.assertIn(".side-nav-tool-list .side-nav-item > a {", stylesheet)
        self.assertIn(".side-nav-item.text-only > a {", stylesheet)
        self.assertIn("gap: 0;", stylesheet)
        self.assertIn("sidebar_tool_row(tool, show_icon=false)", template)
        self.assertIn(
            "{% if show_icon %}<span class=\"side-nav-icon\"", template
        )

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
        self.assertIn('.ping-host-option[data-state="healthy"] .ping-host-state-dot {', stylesheet)
        self.assertIn('.ping-host-option[data-state="degraded"] .ping-host-state-dot {', stylesheet)
        self.assertIn('.ping-host-option[data-state="down"] .ping-host-state-dot {', stylesheet)
        self.assertIn(".ping-graph-card {", stylesheet)
        self.assertIn(".ping-host-statistics .ping-statistics span {", stylesheet)
        self.assertIn("display: inline-flex;", stylesheet)
        self.assertIn(
            "grid-template-columns: minmax(150px, 28%) minmax(0, 1fr) auto;",
            stylesheet,
        )
        self.assertIn(".ping-graph-card .ping-host-statistics {", stylesheet)
        self.assertIn(".ping-graph-card .ping-history-canvas {", stylesheet)
        self.assertIn("max-width: 100%;", stylesheet)
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
        self.assertIn("new ResizeObserver((entries) => {", script)
        self.assertIn("const cssWidth = Math.floor(view.chart.clientWidth);", script)
        self.assertIn("if (cssWidth <= 0) return;", script)
        self.assertIn('data-view-mode="graphs"', (TEMPLATE_ROOT / "tools" / "_ping_results.html").read_text(encoding="utf-8"))
        self.assertIn('data-ping-size="small"', (TEMPLATE_ROOT / "tools" / "_ping_results.html").read_text(encoding="utf-8"))
        self.assertIn('id="ping-health-grid"', (TEMPLATE_ROOT / "tools" / "_ping_results.html").read_text(encoding="utf-8"))
        self.assertIn('id="ping-grid-preview"', (TEMPLATE_ROOT / "tools" / "_ping_results.html").read_text(encoding="utf-8"))
        self.assertIn("function healthState(result, series)", script)
        self.assertIn("function showGridPreview(host, anchor, pinned = false)", script)
        self.assertIn("const cssHeight = view.variant === \"preview\"", script)
        self.assertIn("{small: 110, medium: 170, large: 240}", script)
        self.assertIn('.ping-health-card[data-state="degraded"] {', stylesheet)
        self.assertIn(".ping-grid-preview {", stylesheet)
        self.assertIn(".ping-popout-page {", stylesheet)

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
        self.assertIn("multicast-mode-icon", template)
        self.assertIn("multicast-live-panel", template)
        self.assertIn("multicast-live-timeline", template)
        self.assertIn("multicast-cancel", template)
        self.assertIn("Download JSON", template)
        self.assertIn("one million packets per run", template)
        self.assertIn(".multicast-mode-picker {", stylesheet)
        self.assertIn(".multicast-mode-card:has(input:focus-visible)", stylesheet)
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
