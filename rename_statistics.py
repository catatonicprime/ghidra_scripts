import ghidra.app.decompiler as decomp

sym_table = currentProgram.getSymbolTable()

stats = {'All Symbols': 0,'User Defined': 0, 'Percent defined by User': 0.0}
for symbol in sym_table.getSymbols():
  stats['All Symbols'] = stats['All Symbols'] + 1
  stats['User Defined'] = stats['User Defined'] + 1 if symbol.get

