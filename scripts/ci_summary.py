#!/usr/bin/env python3
"""Parsira JUnit XML izvješća pytesta i ispisuje SAŽETAK PO VJEŽBI kao GitHub anotacije.

Koristi se u CI-u (vidi .github/workflows/ci.yml):

    python scripts/ci_summary.py --branch <grana> \
        --functional reports/functional.xml --security reports/security.xml

Ciljno stanje:
  - grana != rjesenja (npr. main): svaka vježba lab01..lab15 MORA imati barem jedan pali
    sigurnosni test (dokaz ranjivosti); svi funkcionalni testovi moraju prolaziti.
  - grana == rjesenja: svi testovi (sigurnosni i funkcionalni) moraju prolaziti.
Izlazni kod != 0 ako ciljno stanje nije zadovoljeno.
"""

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET

LABS = [f"lab{n:02d}" for n in range(1, 16)]


def parse(path: str) -> dict[str, dict[str, int]]:
    """Vraća {lab: {"total": t, "failed": f}} iz jednog JUnit XML izvješća."""
    result = {lab: {"total": 0, "failed": 0} for lab in LABS}
    if not path or not os.path.isfile(path):
        return result
    root = ET.parse(path).getroot()  # noqa: S314 - izvješće generira naš vlastiti CI
    for case in root.iter("testcase"):
        match = re.search(r"lab(\d\d)", case.get("classname", "") + " " + case.get("file", ""))
        if not match or ("lab" + match.group(1)) not in result:
            continue
        lab = "lab" + match.group(1)
        if case.find("skipped") is not None:
            continue
        result[lab]["total"] += 1
        if case.find("failure") is not None or case.find("error") is not None:
            result[lab]["failed"] += 1
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", ""))
    parser.add_argument("--functional", default="reports/functional.xml")
    parser.add_argument("--security", default="reports/security.xml")
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    functional = parse(args.functional)
    security = parse(args.security)
    is_solution = args.branch == "rjesenja"
    lines, problems = [], []

    for lab in LABS:
        sec, fun = security[lab], functional[lab]
        if sec["total"] == 0:
            status = "NEMA SIG. TESTOVA"
            problems.append(f"{lab}: nedostaje sigurnosni test")
        elif is_solution:
            if sec["failed"] == 0:
                status = f"ISPRAVLJENO ({sec['total']}/{sec['total']} sig. testova prolazi)"
            else:
                status = f"NIJE ISPRAVLJENO ({sec['failed']}/{sec['total']} sig. testova pada)"
                problems.append(f"{lab}: sigurnosni testovi i dalje padaju ({sec['failed']}/{sec['total']})")
        elif sec["failed"] == 0:
            status = f"NIJE RANJIVO?! (0/{sec['total']} sig. testova pada)"
            problems.append(f"{lab}: niti jedan sigurnosni test ne pada - ranjivost nije dokazana")
        else:
            status = f"RANJIVO ({sec['failed']}/{sec['total']} sig. testova pada)"
        if fun["failed"] > 0:
            problems.append(f"{lab}: funkcionalni testovi padaju ({fun['failed']}/{fun['total']})")
            status += f" | FUNKC. PAD ({fun['failed']}/{fun['total']})"
        lines.append(f"{lab}: {status}")

    title = "Lab sazetak (rjesenja)" if is_solution else "Lab sazetak (main)"
    if args.label:
        title += f" {args.label}"
    print(f"::notice title={title}::" + "%0A".join(lines), flush=True)

    print(f"\n===== SAŽETAK PO VJEŽBI ({args.branch or '?'}) {args.label} =====")
    for line in lines:
        print("  " + line)
    print("=" * 50 + "\n")

    if problems:
        for problem in problems:
            print(f"::error title=Ciljno stanje nije zadovoljeno::{problem}", flush=True)
        print(f"NEUSPJEH: {len(problems)} problema (vidi anotacije iznad).")
        return 1
    print("OK: ciljno stanje zadovoljeno.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
