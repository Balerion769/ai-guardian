"""Download 50 labeled OWASP BenchmarkPython cases and score the static scanner.

Run explicitly: python tests/owasp_benchmark.py. This is a network benchmark,
not part of the deterministic unit-test suite.
"""

import asyncio
import csv
import io
import random
import sys

import httpx

from scanner.static_rules import StaticAnalyzer
from scanner.taint import analyze_taint


BENCHMARK_COMMIT = "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"
BASE = f"https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkPython/{BENCHMARK_COMMIT}"


async def _download(client: httpx.AsyncClient, name: str, semaphore: asyncio.Semaphore) -> tuple[str, str]:
    """Retrieve one official source file with a concurrency bound."""
    async with semaphore:
        response = await client.get(f"{BASE}/testcode/{name}.py")
        response.raise_for_status()
        return name, response.text


async def benchmark() -> tuple[int, int, int, int]:
    """Score 25 positive and 25 negative labeled Python cases."""
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        response = await client.get(f"{BASE}/expectedresults-0.1.csv")
        response.raise_for_status()
        rows = list(csv.reader(io.StringIO(response.text)))
        labeled = [(row[0], row[2].strip().lower() == "true") for row in rows if len(row) >= 4 and not row[0].startswith("#")]
        rng = random.Random(42)
        positives = [entry for entry in labeled if entry[1]]
        negatives = [entry for entry in labeled if not entry[1]]
        rng.shuffle(positives)
        rng.shuffle(negatives)
        selected = positives[:25] + negatives[:25]
        if len(selected) != 50:
            raise ValueError("OWASP expected-results file contains fewer than 25 examples of either label")
        semaphore = asyncio.Semaphore(8)
        sources = dict(await asyncio.gather(*(_download(client, name, semaphore) for name, _ in selected)))
    scanner = StaticAnalyzer()
    tp = fp = fn = tn = 0
    for name, expected in selected:
        source = sources[name]
        findings = scanner.analyze(source, "python") + analyze_taint(source, "python")
        predicted = any(f.category != "Analysis Incomplete" for f in findings)
        if expected and predicted:
            tp += 1
        elif expected:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def main() -> int:
    """Print a compact precision/recall table with an explicit failure code."""
    try:
        tp, fp, fn, tn = asyncio.run(benchmark())
    except (httpx.HTTPError, ValueError) as exc:
        sys.stderr.write(f"OWASP benchmark could not run: {type(exc).__name__}: {exc}\n")
        return 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    sys.stdout.write("OWASP BenchmarkPython v0.1 | 50 sampled files | static + taint only\n")
    sys.stdout.write("TP  FP  FN  TN  Precision  Recall\n")
    sys.stdout.write(f"{tp:2}  {fp:2}  {fn:2}  {tn:2}  {precision:9.3f}  {recall:6.3f}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
