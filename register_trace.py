# Experiment with tracing the source value of a register.
# x-refs will have an exponentiating effect probably, at least a multiplicative one.
# We'll probably need to do some loop detection in the control flow (recursive calls for instance)
# When we detect loops we should bail on that path or terminate the trace
# We can probably only search to certain depths (depending on memory available etc)... 
# what if as we're walking back we never find the start?
# Identifying the Entry Point would probably be good to know to help bound this, but also it might just get too big.
# Another interesting affect is that of structured data... e.g. if I load a user-tainted datum into a structured
# element and then pass the structured element (instead of the register) it 

#let's start with a call to a sensitive function...

from ghidra.program.model.symbol import FlowType

data_stack = []

lua_pushcclosure = toAddr(0x02e22900)
lua_pushcclosure_calls = [caller for caller in getReferencesTo(lua_pushcclosure) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]
lua_pushcclosure_calls.sort()

lua_pushcclosure_calls = lua_pushcclosure_calls[:-1] # simplify to just one call to play with... remove to explode your cpu

call = lua_pushcclosure_calls[0]
print(call)

address = call.fromAddress
instr = getInstructionAt(address)
input_objs = instr.getInputObjects()
print (input_objs)