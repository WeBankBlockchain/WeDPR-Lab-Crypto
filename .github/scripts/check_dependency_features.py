#!/usr/bin/env python3
"""Prevent the vulnerable legacy rand logging configuration (RUSTSEC-2026-0097)."""
import json
import subprocess

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1"], text=True))
packages = {package["id"]: package for package in metadata["packages"]}
for node in metadata["resolve"]["nodes"]:
    package = packages[node["id"]]
    if package["name"] == "rand" and package["version"].startswith("0.7."):
        if "log" in node["features"]:
            raise SystemExit("Legacy rand 0.7 must not enable log: RUSTSEC-2026-0097")
        print("Legacy rand " + package["version"] + ": vulnerable log feature is disabled")
