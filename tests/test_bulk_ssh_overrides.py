"""Collapsed row controls must not hide fleet decisions or identity warnings."""
from html.parser import HTMLParser

import pytest
from flask import render_template

from twn_toolkit import create_app
from twn_toolkit.ssh_commandlets import build_ssh_command_plans


class Element:
    def __init__(self, tag, attrs=(), parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children, self.text = [], ''
    def ancestors(self):
        node = self.parent
        while node:
            yield node
            node = node.parent


class Markup(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.root = Element('root')
        self.current = self.root
        self.elements = []
        self.feed(html)
    def handle_starttag(self, tag, attrs):
        node = Element(tag, attrs, self.current)
        self.current.children.append(node)
        self.elements.append(node)
        if tag not in {'input', 'br', 'hr', 'img', 'meta', 'link'}:
            self.current = node
    def handle_endtag(self, tag):
        node = self.current
        while node.parent:
            if node.tag == tag:
                self.current = node.parent
                return
            node = node.parent
    def handle_data(self, text):
        self.current.text += text
    def marked(self, attr):
        return [e for e in self.elements if attr in e.attrs]


@pytest.fixture(scope='module')
def app(tmp_path_factory):
    result = create_app(str(tmp_path_factory.mktemp('override-markup')))
    result.testing = True
    return result


def review_markup(app, count, **form):
    preview = build_ssh_command_plans('Name | Host\n' + '\n'.join(
        f'Fixture {i} | host-{i}.test' for i in range(count)), 'show status', 10)
    preview['selected_actions'] = []
    with app.test_request_context():
        return Markup(render_template('tools/_multi_ssh_connection_choices.html', preview=preview, form=form))


@pytest.mark.parametrize('count', [1, 2, 501])
def test_default_review_keeps_bulk_choices_visible_and_rows_collapsed(app, count):
    page = review_markup(app, count)
    details, = page.marked('data-ssh-host-overrides')
    assert details.tag == 'details' and 'open' not in details.attrs
    assert str(count) in details.children[0].text
    bulk = page.marked('data-ssh-choice-all')
    assert len(bulk) == 2
    assert all(details not in e.ancestors() for e in bulk)
    rows = [e for e in page.elements if e.attrs.get('role') == 'group']
    assert len(rows) == count and all(details in e.ancestors() for e in rows)
    choices = [e for e in page.elements if e.attrs.get('name') in {'unknown_key_hosts','legacy_algorithm_hosts'}]
    assert len(choices) == 2 * count
    assert all('checked' not in e.attrs for e in choices)
    summary, = page.marked('data-ssh-choice-summary')
    assert details not in summary.ancestors()
    assert summary.text.count('0/' + str(count)) == 2
    # Identity verification cannot be mistaken for a completed network preflight.
    warnings = [e for e in page.elements if 'Changed keys always stop' in e.text or 'does not contact hosts' in e.text]
    assert len(warnings) == 2 and all(details not in e.ancestors() for e in warnings)


def test_mixed_choices_are_retained_and_counted_outside_collapsed_rows(app):
    page = review_markup(app, 3, unknown_key_hosts=['host-0.test'],
                         legacy_algorithm_hosts=['host-1.test','host-2.test'])
    checked = {(e.attrs.get('name'), e.attrs.get('value')) for e in page.elements if 'checked' in e.attrs}
    assert checked == {('unknown_key_hosts','host-0.test'),('legacy_algorithm_hosts','host-1.test'),('legacy_algorithm_hosts','host-2.test')}
    summary, = page.marked('data-ssh-choice-summary')
    assert 'Unrecognized keys: 1/3' in summary.text and 'Legacy algorithms: 2/3' in summary.text
    details, = page.marked('data-ssh-host-overrides')
    assert 'open' not in details.attrs and details not in summary.ancestors()
