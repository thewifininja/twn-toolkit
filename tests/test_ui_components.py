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
        self.assertIn("overflow-wrap: anywhere;", stylesheet)

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


if __name__ == "__main__":
    unittest.main()
