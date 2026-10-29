"""Independent flat append and reshape indices for main trace masking."""
import json
import sys
from pathlib import Path

PATH=Path(__file__).resolve().parent/'fixtures/preparation.json'

def corpus():
    cases=[]
    for height,width,columns in [(2,2,4),(4,3,4)]:
        flat=[]
        for row in range(height):
            flat.extend(dict(random=False,index=row*width+c) for c in range(width))
            flat.extend(dict(random=True,index=row*(width+2*columns)+c) for c in range(width+2*columns))
        stride=width+columns
        cases.append(dict(height=height,width=width,columns=columns,draws=height*(width+2*columns),
                          cells=[flat[start:start+stride] for start in range(0,len(flat),stride)]))
    return cases

def main():
    text=json.dumps(corpus(),indent=2)+'\n'
    if sys.argv[1:]==['--check']:
        if PATH.read_text(encoding='utf8')!=text: raise SystemExit('Main preparation reference differs')
        print('Two independent masking layouts match')
    elif not sys.argv[1:]:
        with PATH.open('x',encoding='utf8',newline='\n') as output: output.write(text)
    else: raise SystemExit('Expected --check or no arguments')

if __name__=='__main__': main()
