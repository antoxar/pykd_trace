__author__ = 'antoxar'
from pykd import *
import sys

nt = loadModule( "nt" )
 
class Logs:
    def __init__(self, fileName):
        fName = "c:\\temp\\%s.log" % (fileName[:-4])
        dprintln( "%s" % fName)
        try:
            self.file = open( fName, 'w')
        except IOError as error:
            dprintln("IOError {0:>s}".format(error.message))

    def write( self, message ):
        self.file.write( message + "\n" )

    def __del__(self):
        self.file.close ()

class BpDict:
    def __init__(self, CallbackPtrList, BpHandler):
        self.modDict = [bp(x, BpHandler) for x in CallbackPtrList()]

    def set(self):
        for k in self.modDict:
            k.set()

    def rem(self):
        for k in self.modDict:
            k.remove()

def GetSyscallList():
    serviceTableHeader = loadDWords( nt.KeServiceDescriptorTable, 4 )
    serviceTableStart = serviceTableHeader[0]
    serviceCount = serviceTableHeader[2]
    return loadPtrs( serviceTableStart, serviceCount )

class BpHandlers:
    def __init__(self, name ):
        self.bpobject = None
        self.dropProc = dict()
        self.dr_name = name
        self.bpobject = BpDict( GetSyscallList, self.SysCallbackHandler )
        self.bpobject.rem()
    
    def _GetCurrentProcess(self):
        str = dbgCommand(".printf \"%x\n\", poi(poi(fs:[0x124])+0x50)")
        return int(str, 16)
    
    def SysCallbackHandler(self):
        str = dbgCommand(".printf \"%x\n\", poi(poi(fs:[0x124])+0x50)")
        pr_addr = int(str, 16)
        eprocess = typedVar("nt", "_EPROCESS", pr_addr )
        fileName = ''.join(( chr(a) for a in eprocess.ImageFileName))
        dprintln(repr(fileName))
        if self.dropProc.has_key(pr_addr):
            func = findSymbol(reg("eip"))
            dprintln(repr(func))
            self.dropProc[pr_addr].write(func)
        return DEBUG_STATUS_GO

    def CloseProcessHandler(self):
        dprintln( "CloseProcessHandler" )
        pr_addr = ptrDWord(reg("esp") + 4)
        eprocess = typedVar("nt", "_EPROCESS", pr_addr )
        fileName = ''.join(( chr(a) for a in eprocess.ImageFileName))
        dprintln("test")
        if self.dr_name in fileName:
            if self.dropProc.has_key(pr_addr):
                del self.dropProc[pr_addr]
                self.bpobject.rem()
        return DEBUG_STATUS_GO
    
    def CreateProcessHandler(self):
        dprintln( "CreateProcessHandler" )
        pr_addr = reg("eax")
        eprocess = typedVar("nt", "_EPROCESS", pr_addr )
        fileName = ''.join(( chr(a) for a in eprocess.ImageFileName))
        dprintln("test")
        if self.dr_name in fileName:
            self.dropProc[pr_addr] = Logs(fileName)
            dprintln(repr(self.dropProc))
            self.bpobject.set()
        return DEBUG_STATUS_GO


if __name__ == "__main__":
    if len(sys.argv) == 2:
        handlers = BpHandlers(sys.argv[1])
        b1 = bp( nt.PspInsertProcess, handlers.CreateProcessHandler)
        b2 = bp( nt.PspProcessDelete, handlers.CloseProcessHandler)
        go()
        dprintln("stopped")
    else:
        dprintln( "Bp Tracer" )
        dprintln( "Using "  + sys.argv[0] + " <PROCESS_NAME>" )