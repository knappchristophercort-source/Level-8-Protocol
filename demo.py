#!/usr/bin/env python3
"""Placeholder demo entrypoint for the L8 Protocol reference implementation."""

from l8_reference import attestation, crypto, identity, ledger, observer, sentinel, verifier


def main() -> None:
    modules = [attestation, crypto, identity, ledger, observer, sentinel, verifier]
    print("L8 Protocol scaffold ready:")
    for module in modules:
        print(f"- {module.__name__}")


if __name__ == "__main__":
    main()
