import pytest
from typer.testing import CliRunner
from hecate_runner.cli import app

runner = CliRunner()

def test_run():
    result = runner.invoke(app, ["doctor"])
    print("EXIT CODE:", result.exit_code)
    print("OUTPUT:", result.stdout)

test_run()
