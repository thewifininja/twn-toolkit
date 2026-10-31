"""Inventory declared UI surfaces, without importing or starting the application.

This is a review index, not a claim of runtime coverage. Dynamic registrations,
Jinja includes/macros, and delegated Agent pages need explicit follow-up.
"""
import ast
import csv
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'docs/interaction-audit/inventory.csv'


def inventory():
    rows = []
    for path in sorted((ROOT / 'twn_toolkit').rglob('*.py')):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'ToolLink':
                rows.append(('navigation', str(path.relative_to(ROOT)), node.lineno,
                             '', ast.unparse(node), ''))
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                        and decorator.func.attr in {'route', 'get', 'post', 'put', 'delete', 'patch'}):
                    continue
                route = ast.unparse(decorator.args[0]) if decorator.args else '(dynamic)'
                methods = next((ast.unparse(k.value) for k in decorator.keywords if k.arg == 'methods'), 'GET' if decorator.func.attr == 'route' else decorator.func.attr.upper())
                rows.append(('route', str(path.relative_to(ROOT)), decorator.lineno, node.name, route, methods))
    for path in sorted((ROOT / 'twn_toolkit/templates').rglob('*.html')):
        source = path.read_text()
        rows.append(('template', str(path.relative_to(ROOT)), 1, path.stem, '', ''))
        for match in re.finditer(r'<(form|dialog|details|button|input|select|textarea|a)\b[^>]*>', source, re.S):
            tag = match.group(1)
            markup = ' '.join(match.group().split())
            rows.append((tag, str(path.relative_to(ROOT)), source.count('\n', 0, match.start()) + 1, '', markup, ''))
    for path in sorted((ROOT / 'twn_toolkit/static').glob('*.js')):
        source = path.read_text()
        for match in re.finditer(r'addEventListener\s*\(\s*[\'\"]([^\'\"]+)', source):
            rows.append(('handler', str(path.relative_to(ROOT)), source.count('\n', 0, match.start()) + 1, match.group(1), '', ''))
    return rows


if __name__ == '__main__':
    rows = inventory()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open('w', newline='') as stream:
        writer = csv.writer(stream, lineterminator='\n')
        writer.writerow(('kind', 'source', 'line', 'name_or_event', 'declaration', 'methods', 'coverage'))
        writer.writerows((*row, 'unverified-static-index') for row in rows)
    from collections import Counter
    print(dict(Counter(row[0] for row in rows)))
