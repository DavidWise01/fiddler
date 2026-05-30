import argparse, json, uuid, time
from pathlib import Path

# ── Router implementation: Charlotte's Web four-guard engine ──────────────────
# To swap routers, replace this import with your own call_router() function.
# call_router(prompt, conversation_id=None) must return a dict with at minimum:
#   route (str), action (str), notes (str)
from ares_router import call_router, evaluate_pass_fail

def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def write_jsonl(path: Path, rows):
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["single","multiturn"], required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out_rows = []
    start = time.time()

    if args.mode == "single":
        suite_path = Path(__file__).with_name("ares_suite.jsonl")
        for test in load_jsonl(suite_path):
            run_id = str(uuid.uuid4())
            resp = call_router(test["prompt"])
            verdict = evaluate_pass_fail(test["expected_outcome"], resp.get("route","UNKNOWN"))
            out_rows.append({
                "run_id": run_id,
                "test_id": test["id"],
                "class": test["class"],
                "expected_outcome": test["expected_outcome"],
                "prompt": test["prompt"],
                "router_response": resp,
                "verdict": verdict,
            })
    else:
        suite_path = Path(__file__).with_name("ares_suite_multiturn.jsonl")
        for test in load_jsonl(suite_path):
            conversation_id = str(uuid.uuid4())
            turn_responses = []
            for i, turn in enumerate(test["turns"], start=1):
                resp = call_router(turn, conversation_id=conversation_id)
                turn_responses.append({
                    "turn": i,
                    "prompt": turn,
                    "router_response": resp,
                })
            out_rows.append({
                "conversation_id": conversation_id,
                "test_id": test["id"],
                "class": test["class"],
                "expected_outcome": test["expected_outcome"],
                "turns": turn_responses,
            })

    out_path = Path(args.out)
    write_jsonl(out_path, out_rows)
    dur = time.time() - start
    print(f"Wrote {len(out_rows)} result records to {out_path} in {dur:.1f}s")

if __name__ == "__main__":
    main()
