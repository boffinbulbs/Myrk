"""Independent modular polynomial evaluations in physical bit reversed order."""
import json
import sys
from pathlib import Path

FIELD = 2013265921
GENERATOR = 31
PATH = Path(__file__).resolve().parent / "fixtures/stream.json"


def polynomial(column, point):
    result = 0
    for power in reversed(range(8)):
        coefficient = (power + 1) * (column + 3) + power * power + 11
        result = (result * point + coefficient) % FIELD
    return result


def corpus():
    cases = []
    for height, width, log_blowup, shift in [(16, 3, 2, 31), (32, 2, 1, 17), (8, 1, 0, 1)]:
        output_height = height << log_blowup
        input_root = pow(GENERATOR, (FIELD - 1) // height, FIELD)
        output_root = pow(GENERATOR, (FIELD - 1) // output_height, FIELD)
        bits = output_height.bit_length() - 1
        inputs = [[polynomial(c, pow(input_root, row, FIELD)) for c in range(width)] for row in range(height)]
        outputs = []
        for row in range(output_height):
            exponent = int(format(row, f"0{bits}b")[::-1], 2)
            point = shift * pow(output_root, exponent, FIELD) % FIELD
            outputs.append([polynomial(c, point) for c in range(width)])
        cases.append(dict(height=height, width=width, log_blowup=log_blowup, shift=shift, input=inputs, output=outputs))
    return cases


def main():
    encoded = json.dumps(corpus(), indent=2) + "\n"
    if sys.argv[1:] == ["--check"]:
        if PATH.read_text(encoding="utf8") != encoded:
            raise SystemExit("Streamed polynomial reference differs")
        print("Three independent polynomial domains match")
    elif not sys.argv[1:]:
        with PATH.open("x", encoding="utf8", newline="\n") as output:
            output.write(encoded)
    else:
        raise SystemExit("Expected --check or no arguments")


if __name__ == "__main__":
    main()
