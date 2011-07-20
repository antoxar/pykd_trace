__author__ = 'antoxar'
from pykd import *
import sys
import time
nt = loadModule( "nt" )
 
class Logs:
    def __init__(self):
        fName = 'c:\\temp\\{0:>s}.log'.format(str(time.strftime("%a_%d_%b_%Y_%H_%M", time.gmtime())))
        dprintln( "%s" % fName)
        try:
            self.file = open( fName, 'w')
        except IOError as error:
            dprintln('IOError {0:>s}'.format(error.message))

    def write( self, message ):
        self.file.write( message + "\n" )

#    def __del__(self):
#        self.file.close()

class BpDict:
    def __init__(self, CallbackPtrList ):
        self.bplist = CallbackPtrList()
        self.modDict = list()
        
    def setHandler(self, BpHandler):
        self.modDict = [bp(x, BpHandler) for x in self.bplist]
        
    def set(self):
        for k in self.modDict:
            k.set()

    def rem(self):
        for k in self.modDict:
            k.remove()

class BpHandlers:

    def __init__(self, name, bplist ):
        self.bpobject = None
        self.dropProc = list()
        self.logs = Logs()
        self.dr_name = name
        self.bpobject = bplist

    def __del__(self):
        del self.logs
        
    def GetCurrentProcess(self):
        str = dbgCommand(".printf \"%x\n\", poi(poi(fs:[0x124])+0x50)")
        return int(str, 16)
    
    def SysCallbackHandler(self):
        pr_addr = self.GetCurrentProcess()
        eprocess = typedVar("nt", "_EPROCESS", pr_addr )
        if eprocess.UniqueProcessId in self.dropProc:
            func = findSymbol(reg("eip"))
            dprintln(repr(func))
            self.logs.write(func)
        return DEBUG_STATUS_GO

    def CloseProcessHandler(self):
        #dprintln( "CloseProcessHandler" )
        pr_addr = ptrDWord(reg("esp") + 4)
        eprocess = typedVar("nt", "_EPROCESS", pr_addr )
        if eprocess.UniqueProcessId in self.dropProc:
            self.dropProc.remove(eprocess.UniqueProcessId)
            dprintln("Rem UniqueProcessId %x" % eprocess.UniqueProcessId)
            self.bpobject.rem()
        return DEBUG_STATUS_GO
    
    def CreateProcessHandler(self):
        #dprintln( "CreateProcessHandler" )
        pr_addr = reg("eax")
        eprocess = typedVar("nt", "_EPROCESS", pr_addr )
        fileName = ''.join( chr(i) for i in eprocess.ImageFileName).rstrip('\x00')
        if eprocess.InheritedFromUniqueProcessId in self.dropProc:
            self.dropProc.append(eprocess.UniqueProcessId)
            dprintln("Add child %x" % eprocess.UniqueProcessId)
        if self.dr_name in fileName:
            self.dropProc.append(eprocess.UniqueProcessId)
            dprintln("Add UniqueProcessId %x" % eprocess.UniqueProcessId)
            self.bpobject.set()
        return DEBUG_STATUS_GO


def GetSyscallList():
    serviceTableHeader = loadDWords( nt.KeServiceDescriptorTable, 4 )
    serviceTableStart = serviceTableHeader[0]
    serviceCount = serviceTableHeader[2]
    return loadPtrs( serviceTableStart, serviceCount )

def start(name):
    bplist = BpDict( GetSyscallList )
    handlers = BpHandlers(name, bplist)
    bplist.setHandler( handlers.SysCallbackHandler)
    bplist.rem()
    b1 = bp( nt.PspInsertProcess, handlers.CreateProcessHandler)
    b2 = bp( nt.PspProcessDelete, handlers.CloseProcessHandler)
    go()
    bplist.rem()
    del handlers.logs
    del handlers

if __name__ == "__main__":
    if len(sys.argv) == 2:
        start(sys.argv[1])
        dprintln("stopped")
    else:
        dprintln( "Bp Tracer" )
        dprintln( "Using "  + sys.argv[0] + " <PROCESS_NAME>" )