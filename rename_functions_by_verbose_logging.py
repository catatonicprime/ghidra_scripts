# Thanks to https://deadc0de.re/articles/ghidra-scripting-python.html for the tutorial :D
# 
import ghidra.app.decompiler as decomp
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.lang import Register
import re

def mangle_name(filename, funcname):
  return "{}/{}".format(filename.lstrip("../"), funcname)

def getArgumentsForCall(call, register_name_map={}):
  # call: location to attempt to discover arguments for.
  # register_name_map: map of registers to a more semantic name, e.g. {"RSI": "function", "RDI": "file"}
  # RSI -> function name
  # RDI -> file name
  if len(register_name_map) == 0:
    raise Exception("register_name_map needs to have at least one {'register': 'name'} pair")
  
  name_value_map = {}
  for name in register_name_map.values():
    name_value_map[name] = None

  parent = getFunctionContaining(call.fromAddress)
  target = currentProgram.getListing().getInstructionAt(call.fromAddress)
  instr = target
  while True:
    instr = instr.previous

    # If we've scanned out of the containing function and didn't find sufficient data to successfully analyze.
    if instr.address < parent.entryPoint:
      return None

    # We need to figure out how to handle MOV instructions or other side-effects.
    if instr.getMnemonicString() in ['MOV'] and instr.getRegister(0) and instr.getRegister(0).getName() in register_name_map:
      return None

    # We're targeting LEA instructions to resolve their scalars for their (probably) string data
    if instr.getMnemonicString() not in ['LEA']:
      continue

    # Get the destination register
    reg = instr.getRegister(0)
    if reg is None:
      continue
    
    # Is this one of the targeted regisers to resolve?
    if reg.getName() not in register_name_map:
      continue

    # If this result has already been found then continue
    value_name = register_name_map[reg.getName()]
    if name_value_map[value_name] is not None:
      continue
    
    # Recover the scalar or bail because we must have missed the copy or it was dynamic
    input_objs = instr.getInputObjects()[0]
    if input_objs is None:
      return None
    if isinstance(input_objs, Register):
      return None

    data_addr = toAddr(input_objs.getValue())
    data_container = getDataContaining(data_addr)
    data = getDataAt(data_addr)
    resolved_data = "" if data is None else data.getValue()
    if not data and data_container:
      resolved_data = data_container.getValue()[data_addr.subtract(data_container.getAddress()):]

    name_value_map[value_name] = resolved_data

    # if there are no remaining values to map (all of them are set) then we're done
    if len([key for key in name_value_map.keys() if name_value_map[key] is None]) == 0:
      break
  return (name_value_map, parent.entryPoint, call)

# TODO: It'd be nice to identify the logv function here to populate this address auto-magically.

logv = getFunctionContaining(askAddress('','wheres the verbose log function?'))
logv_entry = logv.getEntryPoint()

# From the starting spot, find the calling locations.

calls = [caller for caller in getReferencesTo(logv_entry) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]

orphan_calls = [caller for caller in getReferencesTo(logv_entry) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress) is None]

orphan_calls.sort()
calls.sort()


renames = []
for call in calls:
  print("Recovering args for {}".format(call))
  args = getArgumentsForCall(call, {'R8': 'format', 'R9':'function'})
  if args is None:
    continue
  renames.append(args)

print ("Found {} total functions to rename.".format(len(renames)))

filename = None
functionname = None
for rename in renames:
  functionname = str(rename[0]['function']) if rename[0] else None
  filename = rename[0]['format']
  if ".c:" in filename:
    filename = filename[:filename.index('.c:')+2]
  if not re.match("^[a-z0-9_]+$", functionname):
    continue
  
  # if filename is '':
  #   continue
  
  new_name = mangle_name(filename or "_", functionname or "_func_{}".format(rename[1]))
  symbol = getSymbolAt(rename[1])
  # if symbol.getSource() == SourceType.DEFAULT:
  print("{} -> {}".format(rename, new_name))
  # symbol.setName(new_name, SourceType.USER_DEFINED)
  