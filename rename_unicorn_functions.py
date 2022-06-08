# Thanks to https://deadc0de.re/articles/ghidra-scripting-python.html for the tutorial :D
# 
import ghidra.app.decompiler as decomp
from ghidra.program.model.symbol import FlowType
from ghidra.program.model.symbol import SourceType


# TODO: It'd be nice to identify the logv function here to populate this address auto-magically.

logv_addr = toAddr(0x02d1b8d0)
logv = getFunctionContaining(logv_addr)
logv_entry = logv.getEntryPoint()

print("Renaming based on references to {}: {}".format(logv_entry, logv))

# From the starting spot, find the calling locations.

callers = [caller for caller in getReferencesTo(logv_entry) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress)]

orphan_callers = [caller for caller in getReferencesTo(logv_entry) 
           if caller.getReferenceType() == FlowType.UNCONDITIONAL_CALL
             and getFunctionContaining(caller.fromAddress) is None]

orphan_callers.sort()
callers.sort()


def getArgumentsForCaller(call):
  # call: location to attempt to discover arguments for.
  # 
  # RSI -> function name
  # RDI -> file name
  dest_registers = ['RSI','RDI']
  filename = None
  funcname = None
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
    if reg.getName() not in dest_registers:
      continue
    
      input_objs = instr.getInputObjects()[0]
    if input_objs is None:
      return None
      data_addr = toAddr(input_objs.getValue())
      data = getDataAt(data_addr)
    name = "" if data is None else data.getValue()
    if reg.getName() == 'RSI' and funcname is None:
      funcname = name
    if reg.getName() == 'RDI' and filename is None:
      filename = name

    if filename is not None and funcname is not None:
      break
  return (filename, funcname, parent.entryPoint, call)

renames = []
for caller in callers:
  args = getArgumentsForCaller(caller)
  if args is None:
    continue
  renames.append(args)

print ("Found {} total functions to rename.".format(len(renames)))

def mangle_name(filename, funcname):
  return "{}/{}".format(filename.lstrip("../"), funcname)

for rename in renames:
  new_name = mangle_name(rename[0] or "_", rename[1] or "_func_{}".format(rename[2]))
  fmt = "} | ".join("{{{{{")+"}"
  print(fmt.format(rename[2], rename[0] or "_", rename[1] or "_func_{}".format(rename[2]), rename[3].fromAddress, new_name))
  #symbol = getFunctionAt(rename[2])
  #symbol.setName(new_name, SourceType.USER_DEFINED)
  #print(symbol)