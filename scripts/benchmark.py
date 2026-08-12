#!/usr/bin/env python3
"""Run the MalIR benchmark from a source checkout."""

from malir.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["benchmark", *(__import__("sys").argv[1:])]))
