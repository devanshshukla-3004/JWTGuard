import argparse, json, sys
from pathlib import Path
from jwtguard.analyzer import JWTError, analyze_token

def main():
    parser=argparse.ArgumentParser(description="Offline JWT structure/claims analyzer; signatures are not verified.")
    parser.add_argument("token",nargs="?")
    parser.add_argument("--file")
    parser.add_argument("--output",default="reports/jwtguard-report.json")
    parser.add_argument("--csv",dest="csv_path")
    args=parser.parse_args()
    if bool(args.token)==bool(args.file): parser.error("provide exactly one token argument or --file PATH")
    try:
        token=Path(args.file).read_text(encoding="utf-8").strip() if args.file else args.token
        report=analyze_token(token)
    except (OSError,JWTError) as exc:
        print("JWTGuard error: "+str(exc),file=sys.stderr); return 2
    print(json.dumps(report,indent=2))
    target=Path(args.output); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    if args.csv_path:
        import csv
        path=Path(args.csv_path); path.parent.mkdir(parents=True,exist_ok=True)
        fields=["code","severity","title","evidence","recommendation"]
        with path.open("w",newline="",encoding="utf-8") as stream:
            writer=csv.DictWriter(stream,fieldnames=fields); writer.writeheader(); writer.writerows(report["findings"])
    print("JSON report written to: "+args.output)
    if args.csv_path: print("CSV findings written to: "+args.csv_path)
    return 0
if __name__=="__main__": raise SystemExit(main())
