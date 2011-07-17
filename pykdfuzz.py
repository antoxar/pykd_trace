__author__ = 'antoxar'
from pykd import *

dr_name = "dropper"
nt = loadModule( "nt" )

class Logs:
    def __init__(self, fileName):
        fName = "c:\\temp\\%s.log" % (fileName[:-4])
        dprintln( "%s" % fName)
        try:
            self.file = open( fName, 'w')
        except IOError as error:
            dprintln("IOError %s" % (error.message))

    def write( self, message ):
        self.file.write( message + "\n" )

    def __del__(self):
        self.file.close ()

def GetCurrentProcess():
    str = dbgCommand(".printf \"%x\n\", poi(poi(fs:[0x124])+0x50)")
    return int(str, 16)

modDict = dict()
dropProc = dict()


def getFileNameFromEproc( addr ):
    eprocess = typedVar("nt", "_EPROCESS", addr )
    fileName = ''.join(( chr(a) for a in eprocess.ImageFileName))
    return fileName

def SysCallbackHandler():
    global dropProc, modDict
    #dprintln( "SysCallbackHandler" )
    pr_addr = GetCurrentProcess()
    fileName = getFileNameFromEproc( pr_addr )
    dprintln(fileName + "\n")
    #if dr_name in fileName:
    if dropProc.has_key(pr_addr):
        func = findSymbol(reg("eip"))
        dropProc[pr_addr].write(func)

    #    if dropProc.has_key(pr_addr):
    #        pass
    #        #dprintln(repr(modDict[pr_addr]))
    #        #dropProc[pr_addr].write(])
    return DEBUG_STATUS_GO

def CreateProcessHandler():
    global dropProc
    dprintln( "CreateProcessHandler" )
    pr_addr = reg("eax")
    fileName = getFileNameFromEproc( pr_addr )
    dprintln(fileName + "\n")
    if dr_name in fileName:
        dropProc[pr_addr] = Logs(fileName)
        dprintln(repr(dropProc))
        setBp()
    return DEBUG_STATUS_GO

def CloseProcessHandler():
    global dropProc
    dprintln( "CloseProcessHandler" )
    pr_addr = ptrDWord(reg("esp") + 4)
    fileName = getFileNameFromEproc( pr_addr )
    #dprintln("%s" % fileName)
    if dr_name in fileName:
        if dropProc.has_key(pr_addr):
            del dropProc[pr_addr]
            remBp()
    return DEBUG_STATUS_GO

def setBp():
    for k in modDict.keys():
        modDict[k].set()

def remBp():
    for k in modDict.keys():
        modDict[k].remove()

ignore = [ ]
def start():
    global modDict
    serviceTableHeader = loadDWords( nt.KeServiceDescriptorTable, 4 )
    serviceTableStart = serviceTableHeader[0]
    serviceCount = serviceTableHeader[2]
    serviceTable = loadPtrs( serviceTableStart, serviceCount )
    for i in xrange( 0, serviceCount ):
        if not i in ignore:
            modDict[serviceTable[i]] = bp( serviceTable[i], SysCallbackHandler )
    b1 = bp( nt.PspInsertProcess, CreateProcessHandler)
    b2 = bp( nt.PspProcessDelete, CloseProcessHandler)
    remBp()
    go()
    dprintln("stopped")

if __name__ == "__main__":
    start()