"""Independent modular quotient coefficients, coset scaling and coupling."""
import json
import sys
from pathlib import Path

P = 2013265921
G = 31
PATH = Path(__file__).resolve().parent / "fixtures/quotient.json"


def evaluate(coefficients, point):
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * point + coefficient) % P
    return value


def corpus():
    cases = []
    for height, width, log_blowup, shift in [(8, 2, 1, 31), (16, 3, 0, 17)]:
        length = height << (log_blowup + 1)
        root = pow(G, (P-1)//height, P)
        output_root = pow(G, (P-1)//length, P)
        coefficients = [[7+c, 3+c, 2*c+1] + [0]*(height-3) for c in range(width)]
        inputs = [[evaluate(coefficients[c], pow(root,r,P)) for c in range(width)] for r in range(height)]
        masks = [[(11+9*r+17*c) % P for c in range(width)] for r in range(height)]
        transformed = []
        for c in range(width):
            values = [coefficients[c][k]*pow(shift,k,P)%P for k in range(height)] + [0]*(length-height)
            for k in range(height):
                mu = pow(G,k,P)*masks[k][c] % P
                values[k] = (values[k]-mu) % P
                values[height+k] = (values[height+k]+pow(shift,height,P)*mu) % P
            transformed.append(values)
        bits = length.bit_length()-1
        outputs = []
        for row in range(length):
            reverse = int(format(row,f"0{bits}b")[::-1],2)
            point = pow(output_root,reverse,P)
            outputs.append([evaluate(transformed[c],point) for c in range(width)])
        cases.append(dict(height=height,width=width,log_blowup=log_blowup,shift=shift,input=inputs,masks=masks,output=outputs))
    height, chunks = 256, 4
    root = pow(G,(P-1)//(height*chunks),P)
    shifts = [G*pow(root,i,P)%P for i in range(chunks)]
    powers = [pow(s,height,P) for s in shifts]
    cis = []
    for i in range(chunks):
        product = 1
        for j in range(chunks):
            if i != j:
                # Z_j(s_i) = (s_i / s_j)^h - 1 for the normalized coset.
                product = product*(powers[i]*pow(powers[j],-1,P)-1) % P
        cis.append(pow(product,-1,P))
    return dict(cases=cases,coupling=dict(height=height,chunks=chunks,shift=G,shifts=shifts,cis=cis))


def main():
    encoded = json.dumps(corpus(),indent=2)+"\n"
    if sys.argv[1:] == ["--check"]:
        if PATH.read_text(encoding="utf8") != encoded:
            raise SystemExit("Independent quotient reference differs")
        print("Two quotient domains and four coupling constants match")
    elif not sys.argv[1:]:
        with PATH.open("x",encoding="utf8",newline="\n") as output:
            output.write(encoded)
    else:
        raise SystemExit("Expected --check or no arguments")


if __name__ == "__main__":
    main()
