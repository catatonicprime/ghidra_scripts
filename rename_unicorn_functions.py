# Thanks to https://deadc0de.re/articles/ghidra-scripting-python.html for the tutorial :D
# 
import ghidra.app.decompiler as decomp
from ghidra.program.model.symbol import FlowType


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
    if instr.address < parent.entryPoint:
      # This means we didn't find sufficient data.
      return None

    # We need to figure out how to handle MOV instructions
    if instr.getMnemonicString() in ['MOV'] and instr.getRegister(0) and instr.getRegister(0).getName() in dest_registers:
      return None

    # We're targeting LEA instructions to resolve their scalars
    if instr.getMnemonicString() not in ['LEA']:
      continue

    # Get the register used by the
    reg = instr.getRegister(0)
    if reg is None:
      continue
    if reg.getName() not in dest_registers:
      continue
    
    try:
      input_objs = instr.getInputObjects()[0]
      data_addr = toAddr(input_objs.getValue())
      data = getDataAt(data_addr)
    except:
      print("Failed on input objects at instruction {} for call at {}".format(instr.address, call.fromAddress))
      exit()
    name = "" if data is None else data.getValue()
    if reg.getName() == 'RSI':
      funcname = name
    if reg.getName() == 'RDI':
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
  print("{}, {}, {}, {}".format(caller.fromAddress, args[0] or "_", args[1] or "_func_{}".format(args[2]), args[3].fromAddress))

print ("Found {} total functions to rename.".format(len(renames)))
