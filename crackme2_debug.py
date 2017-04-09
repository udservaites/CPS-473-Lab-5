#---------------------------------------------------------------------
# Debug notification hook test
#
# This script start the executable and steps through the first five
# instructions. Each instruction is disassembled after execution.
#
# Author: Gergely Erdelyi <dyce@d-dome.net>
#---------------------------------------------------------------------
from idaapi import *

class MyDbgHook(DBG_Hooks):
    """ Own debug hook class that implementd the callback functions """

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print "Process started, pid=%d tid=%d name=%s" % (pid, tid, name)
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        print "Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code)
        return 0

    def dbg_library_load(self, pid, tid, ea, name, base, size):
        print "Library loaded: pid=%d tid=%d name=%s base=%x" % (pid, tid, name, base)

    def dbg_bpt(self, tid, ea):
    #    print "Break point at 0x%x pid=%d" % (ea, tid)
        if ea == 0x401228:
            pas = '';
            for i in xrange(4202878, 4202894):
                if chr(Byte(i)) is None: break
                pas += chr(Byte(i))
            print pas
        if ea == 0x40123F:
            if GetRegValue("ecx") == 0: #rv = register value
                register_value = idaapi.regval_t()
                register_value.ival = 200 #decimal
                idaapi.set_reg_val("ecx", register_value)
            else:
                register_value = idaapi.regval_t()
                register_value.ival = 0 #decimal
                idaapi.set_reg_val("ecx", register_value)
        continue_process()
        return 0

    def dbg_trace(self, tid, ea):
        print tid, eaa
        return 0

    def dbg_step_into(self):
        print "Step into"
        return self.dbg_step_over()

    def dbg_step_over(self):
        eip = GetRegValue("EIP")
        print "0x%x %s" % (eip, GetDisasm(eip))

        self.steps += 1
        if self.steps >= 5:
            request_exit_process()
        else:
            request_step_over()
        return 0

# Remove an existing debug hook
try:
    if debughook:
        print "Removing previous hook ..."
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

AddBpt(0x401228)
AddBpt(0x40123F)


# Stop at the entry point
ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

# Step one instruction
request_step_over()

# Start debugging
run_requests()
