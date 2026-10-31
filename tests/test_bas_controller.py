"""Prevent automatic BAS when its controller loses nonroot isolation."""

from __future__ import annotations

import copy

import pytest

from hecate_runner.bas.base import SafetyViolationError
from hecate_runner.bas.controller import CONTROLLER_STATE_PATHS, validate_controller


def controller_config():
    return {
        "State": {"Running": True},
        "Config": {"User": "10001:10001", "Labels": {"hecate.role": "caldera-controller"}},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Memory": 1073741824,
            "NanoCpus": 1000000000,
            "PidsLimit": 128,
            "PortBindings": {"8888/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8888"}]},
        },
        "NetworkSettings": {"Networks": {"bridge": {}, "hecate-bas-lab": {}}},
        "Mounts": [
            {"Type": "volume", "Destination": target} for target in CONTROLLER_STATE_PATHS.values()
        ],
    }


def test_reviewed_controller_is_accepted():
    validate_controller(controller_config())


@pytest.mark.parametrize(
    "change",
    [
        {"ReadonlyRootfs": False},
        {"Privileged": True},
        {"CapAdd": ["SYS_ADMIN"]},
        {"SecurityOpt": ["no-new-privileges=true", "seccomp=unconfined"]},
        {"Memory": 0},
        {"PidsLimit": 0},
        {"PortBindings": {"8888/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8888"}]}},
    ],
)
def test_weakened_controller_is_refused(change):
    controller = controller_config()
    controller["HostConfig"].update(change)
    with pytest.raises(SafetyViolationError):
        validate_controller(controller)


def test_root_or_host_bind_mounts_are_refused():
    original = controller_config()
    for mutate in (
        lambda c: c["Config"].update(User="0:0"),
        lambda c: c["Mounts"][0].update(Type="bind"),
        lambda c: c["Mounts"].append({"Type": "volume", "Destination": "/usr/src/app/app"}),
        lambda c: c["NetworkSettings"]["Networks"].update({"unexpected": {}}),
    ):
        candidate = copy.deepcopy(original)
        mutate(candidate)
        with pytest.raises(SafetyViolationError):
            validate_controller(candidate)
