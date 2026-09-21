import pytest
from typer.testing import CliRunner
from hecate_runner.cli import app
import os

runner = CliRunner()

def test_run():
    os.environ["HECATE_RUNNER_CTI_PROVIDER"] = "file"
    result = runner.invoke(app, ["doctor"])
    print("EXIT CODE:", result.exit_code)
    print("OUTPUT:", result.stdout)

test_run()
