from __future__ import annotations

import re
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
        self.assertIn("scrollToCursor()", emulator)
        self.assertIn('id="remote-terminal-width"', workspace)
        self.assertIn("syncTerminalGeometry(selected)", script)
        self.assertNotIn("window.addEventListener(\"resize\", scheduleResize)", script)

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

    def test_ping_and_dns_use_compact_saved_profile_controls(self) -> None:
        ping_template = (TEMPLATE_ROOT / "tools" / "ping.html").read_text(
            encoding="utf-8"
        )
        dns_template = (TEMPLATE_ROOT / "tools" / "dns_response.html").read_text(
            encoding="utf-8"
        )
        script = (TEMPLATE_ROOT.parent / "static" / "saved-profile-manager.js").read_text(
            encoding="utf-8"
        )
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertEqual(ping_template.count("compact=true"), 1)
        self.assertEqual(dns_template.count("dns-inline-profile-manager"), 2)
        for template in (ping_template, dns_template):
            self.assertIn("data-saved-profile-primary", template)
            self.assertIn("data-saved-profile-more", template)
            self.assertIn("data-saved-profile-naming", template)
            self.assertIn("data-saved-profile-cancel", template)
        self.assertIn('openNaming("new")', script)
        self.assertIn('openNaming("rename")', script)
        self.assertIn('primary.textContent = hasSavedProfile ? "Save changes" : "Save current…"', script)
        self.assertIn(".compact-profile-controls {", stylesheet)
        self.assertIn(".compact-profile-naming[hidden]", stylesheet)
        self.assertIn(".compact-profile-controls .toolkit-select-trigger,", stylesheet)
        self.assertIn("height: var(--ui-control-height);", stylesheet)

    def test_selects_use_the_shared_theme_aware_control(self) -> None:
        base_template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        script = (TEMPLATE_ROOT.parent / "static" / "select-control.js").read_text(
            encoding="utf-8"
        )
        appearance = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )

        self.assertIn("select-control.js", base_template)
        self.assertIn('trigger.setAttribute("role", "combobox")', script)
        self.assertIn('menu.setAttribute("role", "listbox")', script)
        self.assertIn('button.setAttribute("role", "option")', script)
        self.assertIn('select.dispatchEvent(new Event("change", {bubbles: true}))', script)
        self.assertIn("new MutationObserver", script)
        self.assertIn("select.multiple", script)
        self.assertIn("window.TwnSelectControls", script)
        self.assertIn(".toolkit-select-chevron {", appearance)
        self.assertIn(".toolkit-select-menu {", appearance)
        self.assertIn('content: "✓";', appearance)

    def test_file_pickers_use_the_shared_theme_aware_control(self) -> None:
        appearance = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )

        self.assertIn('input[type="file"]::file-selector-button {', appearance)
        self.assertIn(
            "background: var(--action-secondary) !important;",
            appearance,
        )
        self.assertIn(
            'input[type="file"]::file-selector-button:hover {',
            appearance,
        )
        self.assertIn("border-color: var(--depth-primary) !important;", appearance)

    def test_tiled_surfaces_and_mobile_actions_keep_shared_geometry(self) -> None:
        appearance = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "main :is(article, details) { border-radius: var(--ui-radius) !important; }",
            appearance,
        )
        self.assertIn(
            "main :is(.link-button, .link-button.subtle) { min-height: 36px !important; }",
            appearance,
        )
        self.assertIn(".multi-ssh-matrix-row-actions .link-button", appearance)
        add_icon_rule = stylesheet.split(".multi-ssh-sheet-add > span {", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("border-radius: var(--ui-radius, 0);", add_icon_rule)

    def test_multicast_firewall_warning_uses_palette_surfaces(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        appearance = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "background: color-mix(in srgb, var(--panel), var(--warn) 8%);",
            stylesheet,
        )
        self.assertIn(
            "background: var(--surface-inset, var(--panel));",
            stylesheet,
        )
        self.assertIn(".multicast-pf-warning pre code {", stylesheet)
        self.assertIn("border-radius: var(--ui-radius, 0);", stylesheet)
        self.assertIn(
            "background: color-mix(in srgb, var(--panel), var(--warn) 10%);",
            appearance,
        )

    def test_help_and_release_notes_use_squared_theme_geometry(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        for selector in (
            ".help-card {",
            ".help-search small:not(:empty) {",
            ".help-toc a {",
            ".help-topic {",
            ".release-note-archive {",
            ".help-topic-body code {",
            ".help-topic-body pre {",
            ".help-definitions > div {",
        ):
            rule = stylesheet.split(selector, 1)[1].split("}", 1)[0]
            self.assertIn("border-radius: var(--ui-radius, 0);", rule)

    def test_raspberry_pi_networking_uses_shared_theme_geometry(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        pi_styles = stylesheet.split("/* Raspberry Pi networking settings */", 1)[
            1
        ].split("/* LLDP Lab */", 1)[0]

        self.assertEqual(pi_styles.count("border-radius: var(--ui-radius, 0);"), 13)
        self.assertIsNone(re.search(r"border-radius:\s*\d", pi_styles))

    def test_account_management_controls_and_metadata_keep_theme_contrast(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        appearance = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )

        action_rule = stylesheet.split(
            ".card-action-details > summary > .card-action-label {", 1
        )[1].split("}", 1)[0]
        self.assertIn("border: 1px solid var(--line-strong);", action_rule)
        self.assertIn("color: var(--ink);", action_rule)
        self.assertNotIn("color: #fff;", action_rule)
        self.assertIn(".builtin-profile-card > div {", stylesheet)
        self.assertIn(".settings-page :is(", appearance)
        self.assertIn(".settings-page .builtin-profile-card > div {", appearance)
        self.assertIn(
            "color: color-mix(in srgb, var(--ink), var(--muted) 55%);",
            appearance,
        )

    def test_settings_save_actions_do_not_stretch_across_forms(self) -> None:
        template = (TEMPLATE_ROOT / "auth" / "settings.html").read_text(
            encoding="utf-8"
        )
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertEqual(template.count('class="settings-save-action"'), 2)
        action_rule = stylesheet.split(".settings-save-action {", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("justify-self: start;", action_rule)
        self.assertIn("width: auto;", action_rule)

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

    def test_expanded_traceroute_uses_a_dense_responsive_timeline(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        hop_rule = stylesheet.split(".traceroute-hop {", 1)[1].split("}", 1)[0]
        card_rule = stylesheet.split(".traceroute-hop-card {", 1)[1].split(
            "}", 1
        )[0]
        metrics_rule = stylesheet.split(".traceroute-hop-metrics {", 1)[1].split(
            "}", 1
        )[0]
        self.assertIn("grid-template-columns: 30px minmax(0, 1fr);", hop_rule)
        self.assertIn("padding-bottom: 7px;", hop_rule)
        self.assertIn(
            "grid-template-columns: auto minmax(140px, 1fr) minmax(0, auto);",
            card_rule,
        )
        self.assertIn("min-height: 42px;", card_rule)
        self.assertIn("grid-column: 3;", metrics_rule)
        self.assertIn("@media (max-width: 720px)", stylesheet)

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

    def test_sidebar_expands_categories_and_subgroups_in_place(self) -> None:
        primary_stylesheet = (
            TEMPLATE_ROOT.parent / "static" / "styles.css"
        ).read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        sidebar_script = (
            TEMPLATE_ROOT.parent / "static" / "sidebar.js"
        ).read_text(encoding="utf-8")

        self.assertIn('class="side-nav-category-accordion', template)
        self.assertIn("data-nav-favorites", template)
        self.assertIn("document.currentScript.parentElement", template)
        self.assertIn(
            'localStorage.getItem("twn-sidebar-favorites-open")',
            template,
        )
        self.assertLess(
            template.index("document.currentScript.parentElement"),
            template.index("{% if sidebar_favorites %}"),
        )
        self.assertIn('class="side-nav-category-summary"', template)
        self.assertIn('class="side-nav-category-body"', template)
        self.assertIn('class="side-nav-flat-tool-list"', template)
        self.assertIn('class="side-nav-tool-section"', template)
        self.assertIn('data-nav-category="category-{{ loop.index0 }}"', template)
        self.assertIn('data-nav-subgroup="child-{{ child_index }}"', template)
        self.assertNotIn('data-nav-back', template)
        self.assertNotIn('class="side-nav-back"', template)
        self.assertIn(".side-nav-flat-tool-list {", stylesheet)
        self.assertIn(".side-nav-category-accordion {", stylesheet)
        self.assertIn(".side-nav-category-summary {", stylesheet)
        self.assertIn(".side-nav-category-body .side-nav-label", stylesheet)
        self.assertIn(".side-nav-tool-section > summary", stylesheet)
        self.assertIn("Structural fallback for the in-place navigation hierarchy", primary_stylesheet)
        self.assertIn(".side-nav-category-summary,", primary_stylesheet)
        self.assertIn("pointer-events: auto;", primary_stylesheet)
        self.assertIn("overflow-wrap: anywhere;", stylesheet)
        self.assertIn("sidebar_tool_row(tool, show_icon=false, category_label=group.label)", template)
        self.assertIn(
            "{% if show_icon %}<span class=\"side-nav-icon\"", template
        )
        self.assertIn("const openCategory = (category", sidebar_script)
        self.assertIn("const openSubgroup = (subgroup", sidebar_script)
        self.assertIn('querySelectorAll("details[data-nav-category]")', sidebar_script)
        self.assertIn('querySelectorAll("details[data-nav-subgroup]")', sidebar_script)
        self.assertIn('const categoryStorageKey = "twn-sidebar-category";', sidebar_script)
        self.assertIn('const favoritesStorageKey = "twn-sidebar-favorites-open";', sidebar_script)
        self.assertIn("storedFavoritesState === \"1\"", sidebar_script)
        self.assertIn("favoritesSection.open ? \"1\" : \"0\"", sidebar_script)
        self.assertIn("`twn-sidebar-subgroup:${category?.dataset.navCategory", sidebar_script)
        self.assertNotIn("closeFocusPanel", sidebar_script)
        self.assertIn("const expandFocusSidebar = () =>", sidebar_script)
        self.assertIn("const collapseFocusSidebar = () =>", sidebar_script)
        self.assertIn('classList.remove("focus-sidebar-expanded")', sidebar_script)
        self.assertIn(
            '[data-layout="focus"] body.focus-sidebar-expanded .app-layout.with-sidebar',
            stylesheet,
        )
        self.assertIn(
            "grid-template-columns: var(--ui-sidebar-expanded-width) minmax(0, 1fr);",
            stylesheet,
        )
        self.assertIn(
            '[data-layout="focus"] body:not(.focus-sidebar-expanded) .app-sidebar',
            stylesheet,
        )
        self.assertIn(
            ".side-nav-favorites:not([open]) > summary { color: var(--chrome-muted, #9aa8a2); }",
            stylesheet,
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
        results_template = (
            TEMPLATE_ROOT / "tools" / "_ping_results.html"
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
        self.assertIn('data-view-mode="graphs"', results_template)
        self.assertIn('class="ping-results-control-deck"', results_template)
        self.assertIn('class="ping-results-toolbar-actions"', results_template)
        self.assertIn(
            '#ping-results[data-view-mode="grid"] .ping-host-browser {',
            stylesheet,
        )
        self.assertIn("grid-template-rows: auto;", stylesheet)
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
        stylesheet = (
            TEMPLATE_ROOT.parent / "static" / "styles.css"
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
        self.assertIn(
            ".snmp-monitor-set {\n  background: color-mix(in srgb, var(--bg), var(--brand-green) 4%);\n  border: 1px solid var(--line);\n  border-radius: var(--ui-radius, 0);",
            stylesheet,
        )
        self.assertIn(
            ".snmp-monitor-target {\n  background: var(--panel);\n  border: 1px solid var(--line);\n  border-radius: var(--ui-radius, 0);",
            stylesheet,
        )
        self.assertIn(
            ".snmp-monitor-chart-wrap {\n  background: color-mix(in srgb, var(--panel), var(--bg) 32%);\n  border: 1px solid var(--line);\n  border-radius: var(--ui-radius, 0);",
            stylesheet,
        )
        self.assertIn(
            ".graph-close-button {\n  background: color-mix(in srgb, var(--panel), var(--bad) 9%);\n  border: 1px solid color-mix(in srgb, var(--bad), transparent 62%);\n  border-radius: var(--ui-radius, 0);",
            stylesheet,
        )
        self.assertIn(
            ".snmp-rule-card {\n  background: color-mix(in srgb, var(--panel), var(--brand-green) 3%);\n  border: 1px solid var(--line);\n  border-radius: var(--ui-radius, 0);",
            stylesheet,
        )
        self.assertIn(
            ".snmp-result {\n  border: 1px solid var(--line);\n  border-radius: var(--ui-radius, 0);",
            stylesheet,
        )

    def test_port_scanner_uses_compact_guided_configuration(self) -> None:
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        template = (TEMPLATE_ROOT / "tools" / "port_scanner.html").read_text(
            encoding="utf-8"
        )

        self.assertIn('class="compact-tool-form"', template)
        self.assertIn("compact-tool-config-grid port-scan-config-grid", template)
        self.assertEqual(template.count("compact-tool-source-card port-inline-profile"), 2)
        self.assertEqual(template.count("compact=true"), 2)
        self.assertEqual(template.count("data-saved-profile-primary"), 2)
        self.assertEqual(template.count("data-saved-profile-naming"), 2)
        self.assertIn("compact-tool-run-card port-scan-run-card", template)
        self.assertIn("port-scan-options compact-tool-option-grid", template)
        self.assertIn(".port-scan-config-grid {", stylesheet)
        self.assertIn(".port-scan-run-card {", stylesheet)
        self.assertIn(".port-open-only > span {", stylesheet)

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
            "grid-template-rows: auto auto minmax(0, auto) auto;",
            stylesheet,
        )
        self.assertEqual(template.count('rows="5"'), 2)
        self.assertIn("height: 112px;", stylesheet)

    def test_ping_and_dns_shift_from_setup_to_results_without_losing_settings(self) -> None:
        ping_template = (TEMPLATE_ROOT / "tools" / "ping.html").read_text(
            encoding="utf-8"
        )
        dns_template = (TEMPLATE_ROOT / "tools" / "dns_response.html").read_text(
            encoding="utf-8"
        )
        workspace_script = (
            TEMPLATE_ROOT.parent / "static" / "tool-results-workspace.js"
        ).read_text(encoding="utf-8")
        ping_script = (
            TEMPLATE_ROOT.parent / "static" / "ping-tool.js"
        ).read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        base_template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")

        for template in (ping_template, dns_template):
            self.assertIn("data-tool-workspace", template)
            self.assertIn("data-tool-runbar", template)
            self.assertIn("data-tool-settings-panel", template)
            self.assertIn("data-tool-settings-open", template)
            self.assertIn("data-tool-settings-close", template)
        self.assertIn("tool-results-workspace.js", base_template)
        self.assertIn("data-tool-results-anchor", dns_template)
        self.assertIn('form="dns-form"', dns_template)
        self.assertIn("data-dns-rerun", dns_template)
        self.assertIn(">Run again</button>", dns_template)
        self.assertIn(">Edit settings</button>", dns_template)
        self.assertNotIn("Edit &amp; rerun", dns_template)
        self.assertIn(
            'workspaceController.setState("results", {focusResults});', ping_script
        )
        self.assertIn(
            'scrollIntoView({behavior: "smooth", block: "start"})', workspace_script
        )
        self.assertIn('event.key === "Escape"', workspace_script)
        self.assertIn(".tool-setup-panel.is-drawer {", stylesheet)
        self.assertIn(".tool-settings-backdrop:hover,", stylesheet)
        self.assertIn(".tool-settings-backdrop:active {", stylesheet)
        self.assertIn(".tool-workspace > * {", stylesheet)

    def test_ntp_and_traceroute_use_results_first_workspaces(self) -> None:
        ntp_template = (TEMPLATE_ROOT / "tools" / "ntp_test.html").read_text(
            encoding="utf-8"
        )
        traceroute_template = (
            TEMPLATE_ROOT / "tools" / "traceroute.html"
        ).read_text(encoding="utf-8")
        traceroute_script = (
            TEMPLATE_ROOT.parent / "static" / "traceroute.js"
        ).read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        base_template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")

        for template in (ntp_template, traceroute_template):
            self.assertIn("data-tool-workspace", template)
            self.assertIn("data-tool-runbar", template)
            self.assertIn("data-tool-settings-panel", template)
            self.assertIn("data-tool-settings-open", template)
            self.assertIn("data-tool-settings-close", template)
            self.assertIn("data-tool-results-anchor", template)
            self.assertIn(">Run again</button>", template)
            self.assertIn(">Edit settings</button>", template)
            self.assertIn('class="compact-tool-form"', template)
            self.assertIn("compact-tool-config-grid", template)
            self.assertIn("compact-tool-source-card", template)
            self.assertIn("compact-tool-run-card", template)
            self.assertIn("compact=true", template)
            self.assertIn("data-saved-profile-primary", template)
            self.assertIn("data-saved-profile-naming", template)
        self.assertIn("tool-results-workspace.js", base_template)
        self.assertIn(
            'workspaceController.setState("results", {focusResults: true});',
            traceroute_script,
        )
        self.assertIn(
            'runbarCancelButton.addEventListener("click", () => {',
            traceroute_script,
        )
        self.assertNotIn('id="traceroute-cancel"', traceroute_template)
        self.assertIn('status.textContent = "Cancelling active traceroutes…";', traceroute_script)
        self.assertIn(".compact-tool-config-grid {", stylesheet)
        self.assertIn(".compact-tool-config-card {", stylesheet)
        self.assertIn(".compact-tool-run-footer {", stylesheet)
        self.assertIn(".compact-tool-option-grid > label,", stylesheet)
        self.assertIn("grid-template-columns: repeat(3, minmax(0, 1fr));", stylesheet)
        self.assertIn("overflow-wrap: anywhere;", stylesheet)

    def test_result_first_workspaces_cover_applicable_tool_catalog(self) -> None:
        template_names = (
            "api_request.html",
            "certificate_inspector.html",
            "dhcp_discover.html",
            "iperf3.html",
            "multi_sftp.html",
            "multi_ssh.html",
            "multicast.html",
            "packet_capture.html",
            "path_mtu.html",
            "port_scanner.html",
            "radius_test.html",
            "snmp_test.html",
            "subnet_excluder.html",
            "syslog_receiver.html",
            "wake_on_lan.html",
        )
        for name in template_names:
            with self.subTest(template=name):
                template = (TEMPLATE_ROOT / "tools" / name).read_text(
                    encoding="utf-8"
                )
                self.assertIn("data-tool-workspace", template)
                self.assertIn("data-tool-settings-panel", template)
                self.assertIn("data-tool-results-anchor", template)
                self.assertIn("tool_settings_backdrop", template)

        base_template = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        workspace_script = (
            TEMPLATE_ROOT.parent / "static" / "tool-results-workspace.js"
        ).read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )
        self.assertIn("tool-results-workspace.js", base_template)
        self.assertIn("root.twnToolWorkspaceController", workspace_script)
        self.assertIn('if (inResultsState()) {', workspace_script)
        self.assertIn(".tool-runbar {", stylesheet)
        self.assertIn("top: var(--topbar-height);", stylesheet)
        self.assertNotIn(
            "top: calc(var(--topbar-height) + 4px);",
            stylesheet,
        )

    def test_bulk_and_snmp_workspaces_use_compact_task_hierarchy(self) -> None:
        bulk_ssh = (TEMPLATE_ROOT / "tools" / "multi_ssh.html").read_text(
            encoding="utf-8"
        )
        bulk_transfer = (TEMPLATE_ROOT / "tools" / "multi_sftp.html").read_text(
            encoding="utf-8"
        )
        snmp = (TEMPLATE_ROOT / "tools" / "snmp_test.html").read_text(
            encoding="utf-8"
        )
        workspace_tabs = (
            TEMPLATE_ROOT.parent / "static" / "workspace-tabs.js"
        ).read_text(encoding="utf-8")
        stylesheet = (TEMPLATE_ROOT.parent / "static" / "styles.css").read_text(
            encoding="utf-8"
        )

        self.assertLess(bulk_ssh.index("1 · Hosts"), bulk_ssh.index("2 · CLI actions"))
        self.assertLess(bulk_ssh.index("2 · CLI actions"), bulk_ssh.index("3 · Run"))
        self.assertIn('name="host_matrix"', bulk_ssh)
        self.assertIn("Build a host matrix", bulk_ssh)
        self.assertIn("Create CLI action", bulk_ssh)
        self.assertIn("Build this run", bulk_ssh)
        self.assertIn("Add one or more saved actions", bulk_ssh)
        self.assertIn("Saving an action never selects it automatically", bulk_ssh)
        self.assertIn('data-ssh-runbook', bulk_ssh)
        self.assertIn("bulk-transfer-config-grid", bulk_transfer)
        self.assertIn("Targets and access", bulk_transfer)
        self.assertIn("Files to fetch", bulk_transfer)
        self.assertIn("Keep or download", bulk_transfer)
        self.assertIn('class="compact-tool-config-head"', bulk_transfer)
        self.assertIn('role="tablist" aria-label="SNMP workspace"', snmp)
        self.assertIn('data-workspace-tab="tests"', snmp)
        self.assertIn('data-workspace-tab="monitor"', snmp)
        self.assertIn('data-workspace-tab="profiles"', snmp)
        self.assertIn('data-workspace-tabs-key="twn.snmp-workspace-tab"', snmp)
        self.assertIn("sessionStorage", workspace_tabs)
        self.assertIn(".snmp-workspace-tabs {", stylesheet)
        self.assertIn(".bulk-transfer-config-grid {", stylesheet)
        self.assertIn(
            ".tool-setup-panel.is-drawer .multi-ssh-run-grid {",
            stylesheet,
        )
        self.assertIn(
            ".tool-setup-panel.is-drawer .multi-ssh-matrix-facts {",
            stylesheet,
        )

    def test_tool_workspaces_share_the_snmp_tab_language(self) -> None:
        base = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
        fortigate = (TEMPLATE_ROOT / "index.html").read_text(encoding="utf-8")
        fortiauthenticator = (
            TEMPLATE_ROOT / "fortiauthenticator" / "index.html"
        ).read_text(encoding="utf-8")
        radius = (TEMPLATE_ROOT / "tools" / "radius_test.html").read_text(
            encoding="utf-8"
        )
        iperf = (TEMPLATE_ROOT / "tools" / "iperf3.html").read_text(
            encoding="utf-8"
        )
        syslog = (TEMPLATE_ROOT / "tools" / "syslog_receiver.html").read_text(
            encoding="utf-8"
        )
        lldp = (TEMPLATE_ROOT / "tools" / "lldp_lab.html").read_text(
            encoding="utf-8"
        )
        appearance = (TEMPLATE_ROOT.parent / "static" / "appearance.css").read_text(
            encoding="utf-8"
        )
        workspace_tabs = (
            TEMPLATE_ROOT.parent / "static" / "workspace-tabs.js"
        ).read_text(encoding="utf-8")

        self.assertIn("workspace-tabs.js", base)
        for template in (fortigate, fortiauthenticator, radius):
            self.assertIn('data-workspace-tab="workflows"', template)
            self.assertIn('data-workspace-tab="profiles"', template)
        self.assertIn('data-workspace-tab="client"', iperf)
        self.assertIn('data-workspace-tab="server"', iperf)
        self.assertIn("tool-workspace-tabs syslog-task-switch", syslog)
        self.assertIn("'tool-workspace-tabs lldp-workspace-tabs'", lldp)
        self.assertIn(".tool-workspace-tabs {", appearance)
        self.assertIn(".lldp-workspace-tabs > :is(button, a, label)", appearance)
        self.assertIn("ArrowRight", workspace_tabs)
        self.assertIn("sessionStorage", workspace_tabs)
        self.assertIn('data-workspace-tabs-persist="false"', fortigate)
        self.assertIn('data-workspace-tabs-persist="false"', fortiauthenticator)
        self.assertIn('workspace.dataset.workspaceTabsPersist !== "false"', workspace_tabs)

    def test_live_result_metrics_use_deliberate_lines_and_available_height(self) -> None:
        ping_script = (
            TEMPLATE_ROOT.parent / "static" / "ping-tool.js"
        ).read_text(encoding="utf-8")
        snmp_script = (
            TEMPLATE_ROOT.parent / "static" / "snmp-interface-monitor.js"
        ).read_text(encoding="utf-8")
        remote_script = (
            TEMPLATE_ROOT.parent / "static" / "remote-connections.js"
        ).read_text(encoding="utf-8")
        stylesheet = (
            TEMPLATE_ROOT.parent / "static" / "styles.css"
        ).read_text(encoding="utf-8")

        self.assertIn("detail.replaceChildren(loss, jitter)", ping_script)
        self.assertIn("ui.peaks.value.replaceChildren(peakDownload, peakUpload)", snmp_script)
        self.assertIn(".dns-results-panel .preview-table-wrap {", stylesheet)
        dns_rule = stylesheet.split(
            ".dns-results-panel .preview-table-wrap {", 1
        )[1].split("}", 1)[0]
        self.assertIn("max-height: none;", dns_rule)
        self.assertIn("let openedFolders = new Set();", remote_script)
        self.assertNotIn(
            "let openedFolders = new Set((library.folders || [])",
            remote_script,
        )

    def test_automation_stage_editor_places_routes_on_transitions(self) -> None:
        script = (
            TEMPLATE_ROOT.parent / "static" / "automation.js"
        ).read_text(encoding="utf-8")
        stylesheet = (
            TEMPLATE_ROOT.parent / "static" / "styles.css"
        ).read_text(encoding="utf-8")

        self.assertIn("Run Stage ${index + 2} when", script)
        self.assertIn("No continuation rule is needed after this stage.", script)
        self.assertIn('querySelector("[data-stage-policy]")?.addEventListener', script)
        mobile_rule = stylesheet.split("@media (max-width: 700px) {", 1)[1]
        self.assertIn(".automation-stage-toolbar {", mobile_rule)
        self.assertIn("flex-direction: column;", mobile_rule)

    def test_syslog_tools_separate_send_and_receive_workspaces(self) -> None:
        template = (
            TEMPLATE_ROOT / "tools" / "syslog_receiver.html"
        ).read_text(encoding="utf-8")
        script = (
            TEMPLATE_ROOT.parent / "static" / "syslog-tools.js"
        ).read_text(encoding="utf-8")
        stylesheet = (
            TEMPLATE_ROOT.parent / "static" / "styles.css"
        ).read_text(encoding="utf-8")

        self.assertIn('role="tablist"', template)
        self.assertEqual(template.count('role="tab"'), 2)
        self.assertEqual(template.count('role="tabpanel"'), 2)
        self.assertIn('data-initial-syslog-task="{{ selected_syslog_mode }}"', template)
        self.assertEqual(template.count('class="compact-tool-form"'), 2)
        self.assertIn("syslog-send-config-grid", template)
        self.assertIn("syslog-receive-config-grid", template)
        self.assertIn("Collector endpoint", template)
        self.assertIn("Message identity and payload", template)
        self.assertIn("Listener endpoint", template)
        self.assertIn("Capture bounds", template)
        self.assertIn("syslog-tools.js", template)
        self.assertIn('event.key === "ArrowRight"', script)
        self.assertIn(".syslog-task-switch {", stylesheet)
        self.assertIn(".syslog-task-panel[hidden] {", stylesheet)

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
        self.assertEqual(template.count('data-workspace-panel='), 2)
        self.assertIn("iperf-client-results-panel", template)
        self.assertNotIn(
            'class="panel iperf-results-panel" data-workspace-panel=',
            template,
        )
        self.assertIn(".iperf-action-grid {", stylesheet)
        self.assertIn(".iperf-server-result-card {", stylesheet)
        self.assertIn(
            "grid-template-columns: repeat(4, minmax(0, 1fr));",
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
        self.assertIn("tool-workspace-tabs multicast-mode-picker", template)
        self.assertIn("multicast-live-panel", template)
        self.assertIn("multicast-live-timeline", template)
        self.assertIn("multicast-cancel", template)
        self.assertIn("Download JSON", template)
        self.assertIn("one million packets per run", template)
        self.assertIn(".multicast-mode-picker {", stylesheet)
        self.assertIn(".multicast-mode-card:has(input:focus-visible)", stylesheet)
        self.assertIn('class="compact-tool-form multicast-compact-form"', template)
        self.assertIn("compact-tool-config-grid multicast-config-grid", template)
        self.assertIn("multicast-stream-card", template)
        self.assertIn("multicast-receiver-card", template)
        self.assertIn("multicast-generator-card", template)
        self.assertIn("compact-tool-run-card multicast-run-card", template)
        self.assertIn("Group and service", template)
        self.assertIn("Join behavior", template)
        self.assertIn("Bounded network test", template)
        self.assertIn(".multicast-run-body {", stylesheet)
        self.assertIn(".multicast-authorization-block {", stylesheet)
        script = (TEMPLATE_ROOT.parent / "static" / "multicast.js").read_text(
            encoding="utf-8"
        )
        self.assertIn('mode === "path"', script)
        self.assertIn("receiveInterface.options", script)
        self.assertIn("response.body.getReader()", script)
        self.assertIn("handleProgress", script)
        self.assertIn("activeController?.abort()", script)
        self.assertIn('listen: {button: "Listen to group"', script)
        self.assertIn('path: {button: "Run end-to-end test"', script)


if __name__ == "__main__":
    unittest.main()
