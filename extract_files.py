import os
import ghidra.app.decompiler as decomp
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol import SourceType

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
    data_addr = toAddr(input_objs.getValue())
    data = getDataAt(data_addr)
    resolved_data = "" if data is None else data.getValue()

    name_value_map[value_name] = resolved_data

    # if there are no remaining values to map (all of them are set) then we're done
    if len([key for key in name_value_map.keys() if name_value_map[key] is None]) == 0:
      break
  return (name_value_map, parent.entryPoint, call)

# Let's try extracting some files from the preprocessor :D
aware_preprocess_file = getFunctionContaining(askAddress('','wheres the preprocessor?'))
aware_preprocess_file_entry = aware_preprocess_file.getEntryPoint()

preprocess_callers = [caller for caller in getReferencesTo(aware_preprocess_file_entry) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]

basedir = askDirectory('Select Directory', "Select").getAbsolutePath() + "/"
basedir += currentProgram.getName()
unnamed_count = 0
for caller in preprocess_callers:
  args = getArgumentsForCall(caller, {'RDX': 'source', 'RSI': 'path'})
  if args is None:
      continue
  source = args[0]['source']
  path = args[0]['path']
  
  paths = []
  if path == '':
    path = "/unnamed_{}".format(unnamed_count)
    unnamed_count +=1
  if path in paths:
    print("Duplicate of {} found!".format(path))
  else:
    paths.append(path)
  filepath = basedir+path
  print("writing {} bytes from {} to file {}".format(len(source), args[2].fromAddress, filepath))  
  #continue # continue here to skip making files to test first
  try:
    os.makedirs(os.path.dirname(filepath))
  except:
    pass
  with open(filepath, 'w+') as file:
    file.write(source)
