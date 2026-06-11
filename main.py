"""
breach-response-toolkit CLI entry point.

Routes --mode flags to individual modules or the full report pipeline.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import click
from dateutil import parser as date_parser
from pydantic import ValidationError
from rich.console import Console

from src import __version__
from src.breach.classifier import BreachClassifier
from src.breach.nist_mapper import NISTMapper
from src.breach.timer import BreachTimer
from src.models.breach_model import BreachInput, BreachType, DataType, SeverityLevel
from src.pipeline import BreachReportPipeline

console = Console()
DEFAULT_OUTPUT_DIR = Path("outputs")


def _parse_detection(value: str) -> datetime:
    return date_parser.isoparse(value)


def _load_breach_input(input_path: Path) -> BreachInput:
    with input_path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    return BreachInput.model_validate(payload)


@click.group(invoke_without_command=True)
@click.option(
    "--mode",
    type=click.Choice(["report", "timer", "classify", "nist", "notify"]),
    default="report",
    help="Pipeline mode to run.",
)
@click.option("--input", "input_path", type=click.Path(path_type=Path), help="JSON breach input file.")
@click.option("--output", "output_dir", type=click.Path(path_type=Path), default=DEFAULT_OUTPUT_DIR)
@click.option("--breach-id", default="B-UNSET-001")
@click.option("--detection", help="ISO 8601 detection datetime (UTC).")
@click.option(
    "--data-type",
    type=click.Choice([item.value for item in DataType]),
)
@click.option("--records", type=int, default=0)
@click.option("--special-category/--no-special-category", default=False)
@click.option("--encryption/--no-encryption", default=False)
@click.option(
    "--breach-type",
    type=click.Choice([item.value for item in BreachType]),
)
@click.option(
    "--severity",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    help="Severity level for standalone NIST mapping.",
)
@click.version_option(version=__version__, prog_name="breach-response-toolkit")
@click.pass_context
def cli(
    ctx: click.Context,
    mode: str,
    input_path: Path | None,
    output_dir: Path,
    breach_id: str,
    detection: str | None,
    data_type: str | None,
    records: int,
    special_category: bool,
    encryption: bool,
    breach_type: str | None,
    severity: str | None,
) -> None:
    """UK GDPR breach response toolkit — local-first CLI."""
    ctx.ensure_object(dict)
    ctx.obj.update(
        {
            "mode": mode,
            "input_path": input_path,
            "output_dir": output_dir,
            "breach_id": breach_id,
            "detection": detection,
            "data_type": data_type,
            "records": records,
            "special_category": special_category,
            "encryption": encryption,
            "breach_type": breach_type,
            "severity": severity,
        }
    )
    if ctx.invoked_subcommand is None:
        ctx.invoke(run)


@cli.command("run")
@click.pass_context
def run(ctx: click.Context) -> None:
    """Execute the selected --mode handler."""
    options = ctx.obj
    mode = options["mode"]

    try:
        if mode == "report":
            _run_report(options)
        elif mode == "timer":
            _run_timer(options)
        elif mode == "classify":
            _run_classify(options)
        elif mode == "nist":
            _run_nist(options)
        elif mode == "notify":
            _run_notify(options)
    except NotImplementedError as exc:
        console.print(f"[yellow]Not yet implemented:[/yellow] {exc}")
        sys.exit(2)
    except ValidationError as exc:
        console.print("[red]Validation error:[/red]")
        console.print(exc)
        sys.exit(1)


def _run_report(options: dict) -> None:
    if options["input_path"]:
        breach = _load_breach_input(options["input_path"])
    else:
        raise click.ClickException(
            "Report mode requires --input <breach.json> until interactive prompts are implemented."
        )

    pipeline = BreachReportPipeline(output_dir=options["output_dir"])
    result = pipeline.run(breach)
    console.print(f"[green]Report complete.[/green] Breach ID: {result.breach_id}")


def _run_timer(options: dict) -> None:
    if not options["detection"]:
        raise click.ClickException("Timer mode requires --detection <ISO8601 datetime>.")
    detection = _parse_detection(options["detection"])
    timer = BreachTimer(detection, options["breach_id"])
    timer.display()


def _run_classify(options: dict) -> None:
    if options["input_path"]:
        breach = _load_breach_input(options["input_path"])
    else:
        raise click.ClickException(
            "Classify mode requires --input <breach.json> until CLI flags are wired."
        )
    classifier = BreachClassifier()
    result = classifier.classify(breach)
    console.print(result.model_dump_json(indent=2))


def _run_nist(options: dict) -> None:
    if not options["breach_type"]:
        raise click.ClickException("NIST mode requires --breach-type.")
    if not options["severity"]:
        raise click.ClickException("NIST mode requires --severity.")
    mapper = NISTMapper()
    result = mapper.map_breach(
        breach_type=BreachType(options["breach_type"]),
        data_type=DataType(options["data_type"] or DataType.BASIC_CONTACT.value),
        severity=SeverityLevel(options["severity"]),
    )
    console.print(result)


def _run_notify(options: dict) -> None:
    raise NotImplementedError("Notify mode requires an existing evidence log — not yet implemented.")


if __name__ == "__main__":
    cli()
