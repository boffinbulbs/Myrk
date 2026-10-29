"""Independent canonical integer trace for the finite quartic constraint system."""
import json
import sys
from pathlib import Path

FIELD = 2013265921
PATH = Path(__file__).resolve().parent / "fixtures/trace.json"


def trace():
    return [[5 + row, pow(5 + row, 4, FIELD)] for row in range(256)]


def main():
    encoded = json.dumps(trace(), indent=2) + "\n"
    if sys.argv[1:] == ["--check"]:
        if PATH.read_text(encoding="utf8") != encoded:
            raise SystemExit("Independent quartic trace differs")
        print("256 quartic rows match")
    elif not sys.argv[1:]:
        PATH.parent.mkdir(exist_ok=True)
        with PATH.open("x", encoding="utf8", newline="\n") as output:
            output.write(encoded)
    else:
        raise SystemExit("Expected --check or no arguments")


if __name__ == "__main__":
    main()
