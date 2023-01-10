import ghidra.app.decompiler as decomp
from ghidra.program.model.symbol import SourceType

sym_table = currentProgram.getSymbolTable()

stats = {
'All Symbols': 0,
'Analysis': 0,
'Default': 0,
'Imported': 0,
'User Defined': 0,
'Percent defined by User': 0.0
}

for symbol in sym_table.getAllSymbols(False):
  stats['All Symbols'] = stats['All Symbols'] + 1
  if symbol.getSource() == SourceType.ANALYSIS:
    stats['Analysis'] = stats['Analysis'] + 1
  if symbol.getSource() == SourceType.DEFAULT:
    stats['Default'] = stats['Default'] + 1
  if symbol.getSource() == SourceType.USER_DEFINED:
    stats['User Defined'] = stats['User Defined'] + 1
print(stats)

