"""Independent integer mixed radix clock schedule."""
import json
from pathlib import Path
import sys

path = Path(__file__).resolve().parent / 'clock-reference.json'
rows = []
for position in range(32):
    row = [int(position % 4 == column) for column in range(4)]
    row += [int(position // 4 == column) for column in range(8)]
    rows.append(row)
expected = json.dumps(rows, indent=2) + '\n'
if sys.argv[1:] == ['--check']:
    if path.read_text(encoding='utf8') != expected:
        raise SystemExit('Clock schedule reference changed')
    print('Independent clock schedule matches')
elif not sys.argv[1:]:
    path.write_text(expected, encoding='utf8', newline='\n')
else:
    raise SystemExit('Expected --check or no arguments')
