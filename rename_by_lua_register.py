'''
03383b3e 48 8d 35        LEA        RSI,[FUN_033d5110]
            cb 15 05 00
03383b45 e8 b6 ed        CALL       lua_pushcclosure                                 void lua_pushcclosure(lua_State 
            a9 ff
03383b4a 48 8d 35        LEA        RSI,[s_EMBEDDED_CA_CONF_0464f384]                = "EMBEDDED_CA_CONF"
            33 b8 2c 01
03383b51 48 89 df        MOV        RDI,RBX
03383b54 e8 f7 eb        CALL       lua_pushstring                                   void lua_pushstring(lua_State * 
            a9 ff

03383b54 - 03383b45 = 15 byte offsets!
 
02e22900: lua_pushcclosure
02e22750: lua_pushstring
'''

import ghidra.app.decompiler as decomp
import itertools
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol import SourceType


# TODO: This deviates quite a bit from the other version for verbose logging.
# Should probably refactor both into a better tool for handling these resolutions
# at varying levels of depth.

def getArgumentsForCall(call, register_name_map={}):
  '''
  Attempts to recover the scalar string loaded into the requested registers in the register_name_map.

  inputs:
    register_name_map: a dictionary of values in the form of {'register name': 'arbitrary returned name'}
  
  outputs:
    returns a tuple including a name value map which is the {'arbtrary returned name':'the scalar string'}
  '''
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

    if value_name == "addr": 
      name_value_map[value_name] = input_objs
    else:
      data_addr = toAddr(input_objs.getValue())
      data = getDataAt(data_addr)
      resolved_data = "" if data is None else data.getValue()
      name_value_map[value_name] = resolved_data

    # if there are no remaining values to map (all of them are set) then we're done
    if len([key for key in name_value_map.keys() if name_value_map[key] is None]) == 0:
      break
  return name_value_map

# find calls to lua_pushcclosure
lua_pushcclosure = toAddr(0x02e22900)
lua_pushcclosure_calls = [caller for caller in getReferencesTo(lua_pushcclosure) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]
lua_pushcclosure_calls.sort()

lua_pushstring = toAddr(0x02e22750)
lua_pushstring_calls = [caller for caller in getReferencesTo(lua_pushstring) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]
lua_pushstring_calls.sort()

targets = [candidate for candidate in itertools.product(lua_pushstring_calls, lua_pushcclosure_calls) if candidate[0].fromAddress.offset - candidate[1].fromAddress.offset == 15]
renames = []
for target in targets:
  name = getArgumentsForCall(target[0], {'RSI': 'name'})
  if name['name'] == '':
    print("Failed to find name for call: {}".format(target[0]))
    continue
  target_addr = getArgumentsForCall(target[1], {'RSI': 'addr'})
  if target_addr is None:
    print("Failed to find no target found for call: {}".format(target[0]))
    continue
  if target_addr is None:
    print("Failed to find addr for call: {}".format(target[0]))
    continue
  renames.append((target_addr['addr'], name['name']))

for rename in renames:
  new_name = "cimpl_" + rename[1]
  symbol = getFunctionAt(toAddr(rename[0].value))
  print("Renaming {}@{} -> {}".format(symbol,symbol.getEntryPoint(), new_name))
  symbol.setName(new_name, SourceType.USER_DEFINED)

# is the previous instruction an LEA RSI?
# is the source operand of the LEA RSI the address of a the entrypoint to a FUN_?
# Store the FUN_ address for later renaming.

# Find next call
# is next call lua_pushstring?
# is the previous instruction an LEA RSI?
# is the source operaend of the LEA RSI the address of a string?

# Get the string
# Rename the stored FUN_ address
