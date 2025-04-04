'''
transpile symbols from fallout2-re into a script for OllyDbg plugin ODbgScript (https://odbgscript.sf.net/) 
'''
from pathlib import Path

indir = Path('fallout2-re-main')
out_filename = 'fo2_symbols_script.txt'

c_files = list(indir.rglob("*.c"))

with open(out_filename,'w') as out_file:
  for file in c_files:
    print(file)
    with open(file, "r", encoding="utf-8") as in_file:
      lines = in_file.readlines()
    
    address_and_comment = []
    i = 0
    while i < len(lines):
      if lines[i].strip().startswith("// 0x"):
        address = lines[i].replace("// ",'').replace('0x','').strip().strip('_').strip('.')
        comment = lines[i+1].strip().strip(';').strip(' = {')
        out_file.write(f'CMT {address}, "{comment}"\n')
      i+=1
