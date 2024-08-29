# Experiment with tracing the source value of a register.
# x-refs will have an exponentiating effect probably, at least a multiplicative one.
# We'll probably need to do some loop detection in the control flow (recursive calls for instance)
# When we detect loops we should bail on that path or terminate the trace
# We can probably only search to certain depths (depending on memory available etc)... 
# what if as we're walking back we never find the start?
# Identifying the Entry Point would probably be good to know to help bound this, but also it might just get too big.
# Another interesting affect is that of structured data... e.g. if I load a user-tainted datum into a structured
# element and then pass the structured element (instead of the register) it only references the memory address of the
# datum... To be comprehensive we might need to track memory completely or with a taint engine or something.

# but lets just look at limited case that only tracks register taint.

# Example:
# tracking a register argument for an embedded luacclosure call
# We want a mostly concrete result for the value in the register.

#let's start with a call to a sensitive function...

from ghidra.program.model.symbol import FlowType

# ResolveData
# This should return the value of the whatever the important thing
# in the register is. If the register is a pointer, this returns
# the pointer. If the register is a string point, this returns the
# string. So forth and so on...
def resolveData(address, resolveType='address'):
  data_addr = toAddr(address)
  if resolveType == 'address':
    return data_addr
  if resolveType == 'string':
    data = getDataAt(data_addr)
    resolved_data = "" if data is None else data.getValue()
    return resolved_data
  return None

def traceRegisters(call, target_registers):
  # We start at the called from address and then work toward previous instructions.
  address = call.fromAddress
  instr = getInstructionAt(address)
  containing_function = getFunctionContaining(address).getEntryPoint()

  # Don't leave the containing function... if we don't have an answer by then, bail.
  while(address >= containing_function):
    # non-Fallthroughs can look like inter-procedural calls, i.e. a call to another functiont that might affect
    # a register... but tracking into them sounds like a huge pain in the ass & probably not necesary in 
    # simpler use-cases that can still be very useful!
    # Luckily a non-fall through appear to be instructions *after* a call
    instr = instr.getPrevious()
    if not instr:
      break
    if not instr.isFallthrough():
      break
    # print("--- ResultObjects")
    result_objects = instr.getResultObjects()
    if len(result_objects) < 1:
      # Ignore result objects with no results (nop?)
      print("*** Unexpected...  ResultObjects was empty")
      continue

    # Quick n dirty check if the result objects intersect with any of our target registers
    # Note: we're only looking for full registers here, partial registers would
    # need some more consideration.
    if not any(str(item) in target_registers for item in result_objects):
      continue

    input_objs = instr.getInputObjects()[0]
    if input_objs is None:
      print("*** Unexpected...  getInputObjects was empty")
      break
    if isinstance(input_objs, ghidra.program.model.lang.Register):    
      return None
    print(instr.getAddress())
    print("--- Source Data: {}".format(resolveData(input_objs.getValue())))
    break

data_stack = []

lua_pushcclosure = toAddr(0x02e22900)

lua_pushcclosure_calls = [caller for caller in getReferencesTo(lua_pushcclosure) 
          if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL]
lua_pushcclosure_calls_with_containing_function = [caller for caller in lua_pushcclosure_calls 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]

lua_pushcclosure_calls_with_containing_function.sort()

# simplify to just one call to play with... remove to explode your cpu
# lua_pushcclosure_calls_with_containing_function = lua_pushcclosure_calls_with_containing_function[:1]

# Now we have all the calls we want to investigate.

print("--- Calls")
for call in lua_pushcclosure_calls_with_containing_function:
  print(call)
  traceRegisters(call, ['RSI', 'ESI'])



