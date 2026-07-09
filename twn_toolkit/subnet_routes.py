from __future__ import annotations

from flask import Blueprint, render_template, request

from .network_tools import ToolInputError, subtract_subnets


def register_subnet_routes(tools_bp: Blueprint) -> None:
    @tools_bp.route("/subnet-excluder", methods=["GET", "POST"])
    def subnet_excluder():
        supernets = ""
        exclusions = ""
        results: list[str] | None = None
        error = ""
        if request.method == "POST":
            supernets = request.form.get("supernets", "").strip()
            exclusions = request.form.get("exclusions", "").strip()
            try:
                results = subtract_subnets(supernets, exclusions)
            except ToolInputError as exc:
                error = str(exc)
        return render_template(
            "tools/subnet_excluder.html",
            error=error,
            exclusions=exclusions,
            results=results,
            supernets=supernets,
        )
