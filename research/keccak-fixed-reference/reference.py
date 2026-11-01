"""Finite public integer reference. No Rust AIR, proof or acceptance API."""
import json
import os
import sys

P = 2013265921
HERE = os.path.dirname(os.path.abspath(__file__))
COUNTS = {'graph_builds': 0, 'whole_graph_evaluations': 0}


class Refusal(ValueError):
    pass


def require(condition, cause):
    if not condition:
        raise Refusal(cause)


def read(name, limit):
    with open(os.path.join(HERE, name), 'rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'FileBound')
    return data.decode('utf-8')


def tokens(text):
    return text.replace('[', ' ').replace(']', ' ').replace(',', ' ').split()


def hex_words(items):
    require(type(items) is list and len(items) in (24, 25), 'HexShape')
    require(all(type(s) is str and len(s) == 16 and
                all(c in '0123456789abcdef' for c in s) for s in items), 'HexWord')
    return [int(s, 16) for s in items]


def source_hex(text, marker):
    body = text.split(marker, 1)[1].split('];', 1)[0]
    parts = tokens(body)
    require(all(s.startswith('0x') and len(s) == 18 for s in parts), 'SourceHex')
    return hex_words([s[2:].lower() for s in parts])


def load_literals():
    fixture = json.loads(read('fixtures/anchors.json', 16384))
    require(set(fixture) == {'version', 'R', 'RC', 's1', 's2', 'axes'} and
            fixture['version'] == 1, 'FixtureShape')
    r = fixture['R']
    require(type(r) is list and len(r) == 5 and all(type(row) is list and
            len(row) == 5 and all(type(v) is int and 0 <= v < 64 for v in row)
            for row in r), 'RotationShape')
    rc = hex_words(fixture['RC'])
    require(len(rc) == 24, 'RoundCount')
    text = read('evidence/constants.rs', 32768)
    raw_r = tokens(text.split('const R:', 1)[1].split('= [', 1)[1].split('];', 1)[0])
    require(len(raw_r) == 25 and all(s.isdecimal() and len(s) <= 2 for s in raw_r),
            'SourceRotations')
    require([int(s) for s in raw_r] == sum(r, []), 'RotationLiterals')
    require(source_hex(text, 'pub const RC: [u64; 24] = [') == rc, 'RoundLiterals')
    raw_bits = tokens(text.split('const RC_BITS:', 1)[1].split('= [', 1)[1].split('];', 1)[0])
    require(len(raw_bits) == 1536 and all(s in ('0', '1') for s in raw_bits), 'RCBitsShape')
    require([int(s) for s in raw_bits] == [(v >> z) & 1 for v in rc for z in range(64)],
            'RCBitsLiterals')
    s1, s2 = hex_words(fixture['s1']), hex_words(fixture['s2'])
    primary = read('evidence/xkcp.rs', 16384).split('fn keccak_f1600()', 1)[1]
    require(source_hex(primary, 'let before = [') == s1 and
            source_hex(primary, 'let after = [') == s2, 'PrimaryLiterals')
    require(len(s1) == len(s2) == 25, 'PrimaryShape')
    return r, rc, s1, s2, fixture['axes']


def at(x, y, z):
    return 64 * (x + 5 * y) + z


def route(r, x, y, z):
    a, b = (x + 3 * y) % 5, x
    return a, b, (z - r[a][b]) % 64


def word_bits(words):
    require(type(words) is list and len(words) == 25, 'InputShape')
    require(all(type(v) is int and 0 <= v < (1 << 64) for v in words), 'InputWord')
    return [(v >> z) & 1 for v in words for z in range(64)]


def pack(bits, width):
    require(len(bits) % width == 0, 'PackingShape')
    return [sum(bits[i + z] << z for z in range(width))
            for i in range(0, len(bits), width)]


def unpack(limbs):
    return [(v >> z) & 1 for v in limbs for z in range(16)]


def build(r, rc, alternative='original'):
    nodes, rounds, references = [], [], 0

    def node(op, a, b=-1):
        nonlocal references
        dest = 1600 + len(nodes)
        require(0 <= a < dest and (op >= 2 or 0 <= b < dest), 'BuildReference')
        nodes.append((op, a, b))
        references += 1 if op >= 2 else 2
        return dest

    a = list(range(1600))
    for turn in range(24):
        c = []
        for x in range(5):
            for z in range(64):
                value = a[at(x, 0, z)]
                for y in range(1, 5):
                    value = node(0, value, a[at(x, y, z)])
                c.append(value)
        d = [node(0, c[64 * ((x + 4) % 5) + z],
                  c[64 * ((x + 1) % 5) + (z + 63) % 64])
             for x in range(5) for z in range(64)]
        t = [node(0, a[at(x, y, z)], d[64 * x + z])
             for y in range(5) for x in range(5) for z in range(64)]
        b = []
        for y in range(5):
            for x in range(5):
                for z in range(64):
                    sx, sy = ((y + 3 * x) % 5, y) if alternative == 'axes' else ((x + 3 * y) % 5, x)
                    rotation = r[sy][sx] if alternative == 'rotation_index' else r[sx][sy]
                    sz = (z + rotation if alternative == 'right_rotation' else z - rotation) % 64
                    b.append(t[at(sx, sy, sz)])
        v, u = [], [0] * 1600
        if alternative == 'chi_inplace':
            for y in range(5):
                for x in range(5):
                    for z in range(64):
                        index = at(x, y, z)
                        w = node(1, b[at((x + 1) % 5, y, z)], b[at((x + 2) % 5, y, z)])
                        u[index] = node(0, b[index], w)
                        b[index] = u[index]
        else:
            for y in range(5):
                for x in range(5):
                    for z in range(64):
                        left, right = b[at((x + 1) % 5, y, z)], b[at((x + 2) % 5, y, z)]
                        v.append(node(1, right, left) if alternative == 'andnot_order' else node(1, left, right))
            u = [node(0, b[i], v[i]) for i in range(1600)]
        out = list(u)
        constant = rc[(turn + 1) % 24] if alternative == 'round_constant' else rc[turn]
        for z in range(64):
            out[z] = node(2 + ((constant >> z) & 1), u[z])
        rounds.append((a, c, t, u, out))
        a = out
    require(len(nodes) == 155136 and references == 308736, 'GraphCounts')
    COUNTS['graph_builds'] += 1
    return nodes, rounds, a


def operation(op, x, y=0):
    if op == 0:
        return (x + y - 2 * x * y) % P
    if op == 1:
        return ((1 - x) * y) % P
    return (x if op == 2 else 1 - x) % P


def assign(graph, inputs):
    require(len(inputs) == 1600, 'BitInputShape')
    values = list(inputs)
    for op, a, b in graph[0]:
        values.append(operation(op, values[a], values[b] if op < 2 else 0))
    COUNTS['whole_graph_evaluations'] += 1
    return values


def equations(graph, values):
    require(len(values) == 156736 and len(graph[0]) == 155136, 'GraphShape')
    require(all(type(v) is int and 0 <= v < P for v in values), 'FieldEncoding')
    for dest, (op, a, b) in enumerate(graph[0], 1600):
        require(op in (0, 1, 2, 3) and 0 <= a < dest and
                ((op < 2 and 0 <= b < dest) or (op >= 2 and b == -1)), 'GraphReference')
        require(values[dest] == operation(op, values[a], values[b] if op < 2 else 0), 'GateEquation')


def check_graph(graph, values):
    require(all(type(v) is int and v in (0, 1) for v in values), 'BitValue')
    equations(graph, values)


def rows_from_graph(graph, values):
    rows = []
    pre = pack(values[:1600], 16)
    for turn, (a, c, t, u, out) in enumerate(graph[1]):
        cv = [values[i] for i in c]
        cp = [cv[64 * x + z] ^ cv[64 * ((x + 4) % 5) + z] ^
              cv[64 * ((x + 1) % 5) + (z + 63) % 64] for x in range(5) for z in range(64)]
        rows.append({'pre': list(pre), 'a': pack([values[i] for i in a], 16),
                     'c': cv, 'cp': cp, 't': [values[i] for i in t],
                     'u': pack([values[i] for i in u], 16),
                     'special': [values[i] for i in u[:64]],
                     'end': pack([values[i] for i in out[:64]], 16),
                     'flags': [int(j == turn) for j in range(24)], 'export': 0})
    return rows


def end_limbs(row):
    return row['end'] + row['u'][4:]


def check_rows(rows, inputs, expected, r, rc):
    source = pack(word_bits(inputs), 16)
    word_bits(expected)
    require(type(rows) is list and len(rows) == 24, 'RowsShape')
    shape = {'pre': 100, 'a': 100, 'c': 320, 'cp': 320, 't': 1600,
             'u': 100, 'special': 64, 'end': 4, 'flags': 24}
    for row in rows:
        require(set(row) == set(shape) | {'export'}, 'RowFields')
        for key, size in shape.items():
            require(type(row[key]) is list and len(row[key]) == size, 'RowShape')
            require(all(type(v) is int and 0 <= v < P for v in row[key]), 'FieldEncoding')
        require(type(row['export']) is int and row['export'] in (0, 1), 'ExportBit')
    require(rows[0]['flags'] == [1] + [0] * 23, 'RoundFlags')
    require(rows[0]['pre'] == source, 'InputBinding')
    for turn, row in enumerate(rows):
        for key in ('c', 't', 'special'):
            require(all(v in (0, 1) for v in row[key]), 'ColumnBit')
        if row['flags'][0]:
            require(row['a'] == row['pre'], 'PreimageBinding')
        require((row['export'] * (1 - row['flags'][23])) % P == 0, 'ExportRound')
        for x in range(5):
            for z in range(64):
                k = 64 * x + z
                cp = operation(0, operation(0, row['c'][k], row['c'][64 * ((x + 4) % 5) + z]),
                               row['c'][64 * ((x + 1) % 5) + (z + 63) % 64])
                require(row['cp'][k] == cp, 'CPrime')
                diff = sum(row['t'][at(x, y, z)] for y in range(5)) - cp
                require((diff * (diff - 2) * (diff - 4)) % P == 0, 'ParityCubic')
        reconstructed = [operation(0, row['t'][at(x, y, z)],
                                  operation(0, row['c'][64 * x + z], row['cp'][64 * x + z]))
                         for y in range(5) for x in range(5) for z in range(64)]
        require(pack(reconstructed, 16) == row['a'], 'ThetaReconstruction')
        b = [row['t'][at((x + 3 * y) % 5, x,
                        (z + 64 - r[(x + 3 * y) % 5][x]) % 64)]
             for y in range(5) for x in range(5) for z in range(64)]
        chi = [operation(0, b[at(x, y, z)], operation(1, b[at((x + 1) % 5, y, z)],
                                                                   b[at((x + 2) % 5, y, z)]))
               for y in range(5) for x in range(5) for z in range(64)]
        require(pack(chi, 16) == row['u'], 'Chi')
        require(pack(row['special'], 16) == row['u'][:4], 'SpecialLane')
        iota = [operation(0, row['special'][z], sum(row['flags'][j] for j in range(24)
                                                 if (rc[j] >> z) & 1)) for z in range(64)]
        require(pack(iota, 16) == row['end'], 'Iota')
        if turn < 23:
            require(rows[turn + 1]['flags'] == row['flags'][-1:] + row['flags'][:-1], 'RoundFlags')
            require(row['pre'] == rows[turn + 1]['pre'], 'PreimageHold')
            require(end_limbs(row) == rows[turn + 1]['a'], 'RoundTransition')
    require(pack(unpack(end_limbs(rows[-1])), 64) == expected, 'OutputBinding')


def reverse_map(graph, rows):
    anchors = {}
    for row, (a, c, t, u, out) in zip(rows, graph[1]):
        for ids, bits in ((a, unpack(row['a'])), (c, row['c']), (t, row['t']),
                          (u, unpack(row['u'])), (out, unpack(end_limbs(row)))):
            for index, value in zip(ids, bits):
                require(index not in anchors or anchors[index] == value, 'AliasBinding')
                anchors[index] = value
    values = [anchors[i] for i in range(1600)]
    for dest, (op, a, b) in enumerate(graph[0], 1600):
        values.append(anchors[dest] if dest in anchors else
                      operation(op, values[a], values[b] if op < 2 else 0))
    check_graph(graph, values)
    return values


def row_refusal(rows, inputs, expected, r, rc):
    try:
        check_rows(rows, inputs, expected, r, rc)
    except Refusal as error:
        return str(error)
    raise AssertionError('Actual mutated rows did not refuse')


def main():
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'RuntimeFlags')
    r, rc, s1, s2, axes = load_literals()
    require(len(axes) == 4 and all(list(route(r, *case[:3])) == case[3:] for case in axes), 'AxisLiterals')
    routes = [at(*route(r, x, y, z)) for y in range(5) for x in range(5) for z in range(64)]
    require(len(set(routes)) == 1600 and min(routes) == 0 and max(routes) == 1599, 'RoutingBijection')
    refusals, outputs, reverse_count, row_restores = [], [], 0, 0
    graph = build(r, rc)
    for inputs, expected in (([0] * 25, s1), (s1, s2)):
        values = assign(graph, word_bits(inputs))
        check_graph(graph, values)
        output = pack([values[i] for i in graph[2]], 64)
        require(output == expected, 'WholePrimaryKAT')
        outputs.append([format(v, '016x') for v in output])
        rows = rows_from_graph(graph, values)
        for export in (0, 1):
            rows[-1]['export'] = export
            check_rows(rows, inputs, expected, r, rc)
            recovered = reverse_map(graph, rows)
            require(recovered == values, 'ReverseValues')
            reverse_count += 1
            del recovered
        rows[-1]['export'] = 0
    for key, turn, index in (('flags', 7, 7), ('pre', 0, 0), ('a', 1, 0),
                             ('end', 23, 0), ('special', 23, 0), ('t', 0, 0), ('c', 0, 0)):
        saved = rows[turn][key][index]
        rows[turn][key][index] = 2 if key in ('t', 'c') else saved ^ 1
        refusals.append(row_refusal(rows, s1, s2, r, rc))
        rows[turn][key][index] = saved
        check_rows(rows, s1, s2, r, rc)
        row_restores += 1
    k = next(i for i in range(99) if rows[0]['a'][i] != rows[0]['a'][i + 1])
    rows[0]['a'][k], rows[0]['a'][k + 1] = rows[0]['a'][k + 1], rows[0]['a'][k]
    refusals.append(row_refusal(rows, s1, s2, r, rc))
    rows[0]['a'][k], rows[0]['a'][k + 1] = rows[0]['a'][k + 1], rows[0]['a'][k]
    check_rows(rows, s1, s2, r, rc)
    row_restores += 1
    wrong = list(s2)
    wrong[0] ^= 1
    refusals.append(row_refusal(rows, s1, wrong, r, rc))
    check_rows(rows, s1, s2, r, rc)
    row_restores += 1
    graph_errors = []
    saved = values[1600]
    values[1600] = 2
    try:
        check_graph(graph, values)
    except Refusal as error:
        graph_errors.append(str(error))
    values[1600] = saved
    check_graph(graph, values)
    saved_node = graph[0][0]
    graph[0][0] = (0, 1600, 0)
    try:
        check_graph(graph, values)
    except Refusal as error:
        graph_errors.append(str(error))
    graph[0][0] = saved_node
    check_graph(graph, values)
    require(graph_errors == ['BitValue', 'GraphReference'], 'ActualGraphRefusals')
    input_errors = []
    for malformed in ([0] * 24, [-1] + [0] * 24, [1 << 64] + [0] * 24, [True] + [0] * 24):
        try:
            word_bits(malformed)
        except Refusal as error:
            input_errors.append(str(error))
    require(input_errors == ['InputShape', 'InputWord', 'InputWord', 'InputWord'], 'ActualInputRefusals')
    del graph, values, rows
    alternatives = ('axes', 'right_rotation', 'rotation_index', 'round_constant', 'andnot_order', 'chi_inplace')
    for alternative in alternatives:
        graph = build(r, rc, alternative)
        values = assign(graph, word_bits(s1))
        require(pack([values[i] for i in graph[2]], 64) != s2, 'AlternativeNotDetected')
        del graph, values
        graph = build(r, rc)
        values = assign(graph, word_bits(s1))
        check_graph(graph, values)
        require(pack([values[i] for i in graph[2]], 64) == s2, 'RestoredPrimary')
        if alternative != alternatives[-1]:
            del graph, values
    del values
    nonbits = [0] * 1600
    nonbits[0] = 2
    values = assign(graph, nonbits)
    equations(graph, values)
    missing_code = ''
    try:
        check_graph(graph, values)
    except Refusal as error:
        missing_code = str(error)
        require(missing_code == 'BitValue', 'MissingBitnessCause')
    else:
        raise AssertionError('Nonboolean state was not refused')
    del values
    values = assign(graph, word_bits(s1))
    check_graph(graph, values)
    require(pack([values[i] for i in graph[2]], 64) == s2, 'FinalRestoredPrimary')
    result = {'format': 'kova.keccak-fixed-reference.result.v1', 'status': 'PASS',
              'scope': 'Unverified public integer reference, no Rust AIR or proof execution',
              'python': sys.version.split()[0], 'primary_kats': 2, 'forward_maps': 2,
              'reverse_maps': reverse_count, 'final_export_values': [0, 1],
              'nodes': len(values), 'operations': len(graph[0]), 'variable_references': 308736,
              'round_constant_bits': 1536, 'rotation_literals': 25, 'routing_bijection': 1600,
              'axis_literals': 4, 'row_refusal_causes': refusals, 'row_restorations': row_restores,
              'graph_refusal_causes': graph_errors, 'input_refusal_causes': input_errors,
              'functional_alternatives': list(alternatives), 'alternative_restorations': 6,
              'missing_bitness_gate_equations_hold': True, 'missing_bitness_actual_refusal': missing_code,
              'whole_graph_evaluations': COUNTS['whole_graph_evaluations'],
              'graph_builds': COUNTS['graph_builds'], 'primary_outputs': outputs}
    require(len(refusals) == row_restores == 9 and reverse_count == 4 and
            COUNTS == {'graph_builds': 13, 'whole_graph_evaluations': 16}, 'ControlCounts')
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode('ascii')
    require(len(encoded) <= 65536, 'OutputBound')
    with open(os.path.join(HERE, 'results', 'result.json'), 'xb') as stream:
        stream.write(encoded)
    print('Whole fixed Keccak integer reference passed: 2 full-state KATs, 4 reverse maps, 6 functional alternatives, 9 row refusals.')


if __name__ == '__main__':
    main()
