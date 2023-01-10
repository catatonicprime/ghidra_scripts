import ghidra.app.decompiler as decomp
from ghidra.program.model.symbol import SourceType

sym_table = currentProgram.getSymbolTable()

output = ""
for symbol in sym_table.getAllSymbols(False):
  if symbol.getSource() == SourceType.USER_DEFINED:
    output = output + str(symbol) + "\n"

with open('symdump.txt', 'w') as fh:
  fh.write(output)