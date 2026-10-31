"""Bounded source constants and conservative lifetimes. No AIR execution."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_NAMES = [
    *['research/signature-packed/src/' + name + '.rs' for name in
      ['layout', 'lib', 'air', 'full_program', 'build', 'packed', 'sources', 'sponge', 'decoding']],
    *['research/signature-storage/src/' + name + '.rs' for name in
      ['ntt', 'matrix', 'program', 'clock', 'activity', 'sampler']],
    *['research/signature-complete-native/src/' + name + '.rs' for name in
      ['keccak', 'mul', 'hints', 'hint_rows', 'packing', 'authorization', 'build/decode', 'build/sample']],
    'research/proof-composition/projection.json',
]


def read(name):
    with (ROOT / name).open('rb') as stream:
        raw = stream.read(131073)
    if len(raw) > 131072:
        raise ValueError('fixed source read bound exceeded')
    return raw.replace(b'\r\n', b'\n')


def arithmetic(expression, environment):
    if len(expression) > 256:
        raise ValueError('constant expression exceeds fixed text bound')
    tree = ast.parse(expression, mode='eval')
    if sum(1 for _ in ast.walk(tree)) > 64:
        raise ValueError('constant expression exceeds fixed node bound')

    def visit(node, depth=0):
        if depth > 16:
            raise ValueError('constant expression exceeds fixed depth')
        if isinstance(node, ast.Constant) and type(node.value) is int:
            value = node.value
        elif isinstance(node, ast.Name) and node.id in environment:
            value = environment[node.id]
        elif isinstance(node, ast.BinOp) and type(node.op) in (ast.Add, ast.Sub, ast.Mult):
            left, right = visit(node.left, depth+1), visit(node.right, depth+1)
            value = left + right if isinstance(node.op, ast.Add) else left - right if isinstance(node.op, ast.Sub) else left * right
        else:
            raise ValueError('unsupported source constant expression')
        if type(value) is not int or not 0 <= value <= 16_777_216:
            raise ValueError('constant outside fixed bounds')
        return value

    return visit(tree.body)


def constants(text, initial=None):
    result = dict(initial or {})
    names = []
    for name, expression in re.findall(r'pub const ([A-Z_0-9]+): usize = ([^;]+);', text):
        if len(names) >= 128:
            raise ValueError('too many source constants')
        if name in result:
            raise ValueError('duplicate source constant')
        expression = expression.replace('crate::mul::WIDTH', 'MUL_WIDTH').replace('crate::hints::WIDTH', 'HINT_WIDTH')
        result[name] = arithmetic(expression, result)
        names.append(name)
    return result, names


FAMILIES = {
    'clock': 'CLOCK',
    'sponge': 'KECCAK MESSAGE OUTPUT',
    'held_private_sources': 'KEY SIGNATURE NOTE SOURCE_PORTS',
    'derived_hashes': 'RHO OWNER TR MU NOTE_COMMITMENT CHALLENGE_XOF',
    'canonical_decoding': 'T1 T1_MESSAGE Z_MESSAGE Z_AUX Z_VALUES',
    'hint_decoding': 'CUTS CUT_COMPLEMENTS CUT_DIFFERENCES HINT_MESSAGE HINT_ACTIVE ACTIVE_LOWER ACTIVE_UPPER GROUP SEGMENT_LOWER SEGMENT_UPPER ONE_HOT HINTS LAST SEEN ORDER',
    'challenge_sampling': 'SIGN_BITS PLUS MINUS COUNT CANDIDATE LOWER UPPER INDEX TAKE OLD_PLUS OLD_MINUS CURSOR CHALLENGE',
    'ntt_outputs': 'NTT_OUTPUT',
    'ntt_workspace': 'NTT_SCRATCH NTT_PRODUCTS NTT_WRITES NTT_FLAGS',
    'matrix_sampling': 'MATRIX_XOF MATRIX_COUNT MATRIX_CURSOR MATRIX_CANDIDATE MATRIX_SLACK MATRIX_TAKE MATRIX_ENABLE',
    'matrix_products': 'EXTRA_PRODUCTS EXTRA_WRITES EXTRA_FLAGS',
    'accumulation': 'ACCUMULATOR',
    'inverse_hints': 'USE_HINT W1',
    'bound_activity': 'ACTIVE_CHALLENGE ACTIVE_MATRIX',
}


def conflicts(lifetimes, banks):
    if len(banks) != 16 or any(type(b) is not int or not 0 <= b < 9 for b in banks):
        raise ValueError('invalid physical output map')
    return [[i,j] for i in range(16) for j in range(i+1,16)
            if banks[i] == banks[j] and max(lifetimes[i][0],lifetimes[j][0]) < min(lifetimes[i][1],lifetimes[j][1])]


def main():
    sources = {name: read(name) for name in SOURCE_NAMES}
    text = {name: raw.decode() for name,raw in sources.items() if name.endswith('.rs')}
    packed = 'research/signature-packed/src/'
    shared = 'research/signature-storage/src/'
    original = 'research/signature-complete-native/src/'
    mul, _ = constants(text[original+'mul.rs'])
    hint, _ = constants(text[original+'hints.rs'])
    layout, names = constants(text[packed+'layout.rs'], {'MUL_WIDTH':mul['WIDTH'], 'HINT_WIDTH':hint['WIDTH']})
    fp, _ = constants(text[packed+'full_program.rs'])
    ntt, _ = constants(text[shared+'ntt.rs'])
    if (layout['HEIGHT'],layout['WIDTH'],layout['PUBLIC_VALUES'],mul['WIDTH'],hint['WIDTH']) != (8192,43176,196,211,125):
        raise ValueError('source layout needs renewed review')
    if (ntt['START'],ntt['END'],fp['MATRIX_START'],fp['MATRIX_END'],fp['POINT_END'],fp['INVERSE_END'],fp['FINAL_END']) != (450,3522,642,3330,3586,5314,5370):
        raise ValueError('source schedule needs renewed review')
    skip = {'HEIGHT','WIDTH','PUBLIC_VALUES','CLOCK_LOW','CLOCK_HIGH','INITIAL_WIDTH','FORWARD_WIDTH'}
    physical = [name for name in names if name not in skip]
    family = {name: group for group,words in FAMILIES.items() for name in words.split()}
    if set(physical) != set(family):
        raise ValueError('missing or unknown region annotation')
    regions = []
    for name, following in zip(physical, physical[1:]+['WIDTH'], strict=True):
        start, end = layout[name], layout[following]
        if not 0 <= start < end <= layout['WIDTH']:
            raise ValueError('nonmonotone physical source region')
        regions.append({'name':name,'columns':[start,end],'width':end-start,'family':family[name],
                        'reuse_certified':False})
    if sum(r['width'] for r in regions) != 43176 or regions[0]['columns'][0] != 0:
        raise ValueError('physical inventory is not complete')
    mapping = ast.literal_eval(re.search(r'OUTPUT_BANKS: \[usize; 16\] = (\[[^;]+\]);',text[packed+'layout.rs'])[1])
    lifetimes = []
    for t in range(16):
        first_write = ntt['START'] + t * ntt['ROWS_PER_TRANSFORM'] + 160
        last_read_end = fp['MATRIX_START'] + (t+1)*8*fp['MATRIX_WINDOW'] if t < 7 else fp['POINT_END'] if t == 7 else fp['POINT_START']+(t-7)*32
        lifetimes.append([first_write,last_read_end])
    if conflicts(lifetimes,mapping):
        raise ValueError('retained whole-bank output mapping conflicts')
    # A separate physical-row calendar crosschecks the interval overlap model.
    peak = max(sum(a <= row < b for a,b in lifetimes) for row in range(8192))
    if peak != 9 or not all(sum(a <= row < b for a,b in lifetimes) == 9 for row in range(3298,3330)):
        raise ValueError('independent conservative peak calendar changed')
    remap_refusals = []
    for bank in range(8):
        candidate = mapping.copy()
        candidate[14] = bank
        bad = conflicts(lifetimes,candidate)
        if not bad:
            raise ValueError('eight-bank remap unexpectedly certified')
        remap_refusals.append({'bank':bank,'conflicting_logical_outputs':bad})
    product_intervals = [[ntt['START']+t*192+32,ntt['START']+t*192+160] for t in range(16)]
    product_intervals += [[fp['INVERSE_START']+i*224+32,fp['INVERSE_START']+i*224+192] for i in range(8)]
    hint_intervals = [[fp['INVERSE_START']+i*224+192,fp['INVERSE_START']+(i+1)*224] for i in range(8)]
    extra_intervals = [[fp['MATRIX_START']+s*48+6,fp['MATRIX_START']+(s+1)*48] for s in range(56)]
    extra_intervals += [[fp['POINT_START'],fp['POINT_END']]]
    active = lambda intervals,row: any(a <= row < b for a,b in intervals)
    counts = {'ntt_products':0,'inverse_hints':0,'both':0,'neither':0,'ntt_and_matrix':0}
    for row in range(8192):
        n, h, e = active(product_intervals,row),active(hint_intervals,row),active(extra_intervals,row)
        counts['ntt_products'] += n
        counts['inverse_hints'] += h
        counts['both'] += n and h
        counts['neither'] += not n and not h
        counts['ntt_and_matrix'] += n and e
    if (counts['ntt_products'],counts['inverse_hints'],counts['both'],counts['neither']) != (3328,256,0,4608):
        raise ValueError('arithmetic phase counts changed')
    if not active(product_intervals,689) or not active(extra_intervals,689) or counts['ntt_and_matrix'] <= 0:
        raise ValueError('known forward and matrix overlap lost')
    invalid = 0
    for expression in ['__import__("os")','UNKNOWN+1','True','2**40']:
        try:
            arithmetic(expression,{})
        except ValueError:
            invalid += 1
    if invalid != 4:
        raise ValueError('unsupported constant expression accepted')
    old = json.loads(sources['research/proof-composition/projection.json'])['conditional_packed_relation']
    removed_columns = 8 * hint['WIDTH'] - 2
    conditional = {'status':'source design only, no candidate constraint implementation',
        'height':8192,'width':43176-removed_columns,'public_values':196,
        'constraint_count':None,'constraint_degree':None,'net_removed_columns':removed_columns,
        'field_payload_bytes':old['reserved_field_bytes'] - 19*8192*4*removed_columns,
        'main_query_fields_at_64_distinct_indices_bytes':old['main_query_fields_at_64_distinct_indices_bytes']-64*4*removed_columns,
        'execution_admitted':False}
    result = {'format':'kova.packed-lifetimes.inventory.v1','scope':'source constants and conservative phase metadata, no AIR or proof execution',
        'source_files':{name:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for name,raw in sources.items()},
        'physical_regions':regions,'physical_columns':43176,'public_values':196,
        'output_banks':mapping,'conservative_output_lifetimes':lifetimes,'whole_bank_calendar_peak':peak,
        'eight_bank_remap_refusals':remap_refusals,'arithmetic_phase_counts':counts,
        'constant_expression_refusals':invalid,'conditional_mode_overlay':conditional,
        'limitations':['Family lifetime descriptions are reviewed annotations, not automatic dataflow extraction',
            'Whole-bank intervals overapproximate coefficient lifetimes and do not prove a general register lower bound',
            'Disjoint active phases do not remove dormant equations or certify register aliasing',
            'Current AIR, constructor, source limits and proof security settings remain unchanged']}
    encoded = json.dumps(result,indent=2,sort_keys=True).encode()+b'\n'
    if len(encoded) > 65536:
        raise ValueError('fixed inventory output cap exceeded')
    with (HERE/'inventory.json').open('xb') as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    print('Source region inventory and conservative calendar checks passed. No alias or proof execution admitted.')


if __name__ == '__main__':
    main()
