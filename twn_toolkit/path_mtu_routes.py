from __future__ import annotations

from flask import Blueprint, render_template, request

from .diagnostic_tools import test_path_mtu
from .network_tools import ToolInputError


def register_path_mtu_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/path-mtu", methods=["GET", "POST"])
    def path_mtu():
        form = {"host": "", "family": "auto", "minimum": "576", "maximum": "1500", "timeout": "1"}
        result = None
        error = ""
        if request.method == "POST":
            form = {key: request.form.get(key, default).strip() for key, default in form.items()}
            try:
                result = test_path_mtu(
                    form["host"],
                    family=form["family"],
                    minimum=int(form["minimum"]),
                    maximum=int(form["maximum"]),
                    timeout=float(form["timeout"]),
                )
            except (ToolInputError, TypeError, ValueError) as exc:
                error = str(exc) or "Enter valid Path MTU settings."
        return render_template("tools/path_mtu.html", form=form, result=result, error=error)
