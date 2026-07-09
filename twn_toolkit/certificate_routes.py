from __future__ import annotations

from flask import Blueprint, render_template, request

from .certificate_tools import (
    CertificateInspectionError,
    inspect_certificate_chain,
    normalize_certificate_target,
)


def register_certificate_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/certificate-inspector", methods=["GET", "POST"])
    def certificate_inspector():
        form = {"target": "", "port": "443", "timeout": "8"}
        result = None
        error = ""
        if request.method == "POST":
            form = {key: request.form.get(key, "").strip() for key in form}
            try:
                host, port = normalize_certificate_target(form["target"], form["port"])
                timeout = float(form["timeout"])
                result = inspect_certificate_chain(host, port, timeout)
                form["port"] = str(port)
            except (CertificateInspectionError, ValueError) as exc:
                error = str(exc)
        return render_template(
            "tools/certificate_inspector.html",
            error=error,
            form=form,
            result=result,
        )
