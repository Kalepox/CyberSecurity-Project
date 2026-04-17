import argparse
import json
from pathlib import Path

from src.loader import load_json

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input JSON file")
    parser.add_argument("--output", required=True, help="Output JSON file")
    return parser.parse_args()


def main():
    args = parse_args()

    messages = load_json(Path(args.input))

    result = {} # analyze_messages

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()