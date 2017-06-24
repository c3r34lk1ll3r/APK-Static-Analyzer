import sys
import os
from optparse import OptionParser
from lib.apk import APK
from lib.decompiler import DexFile

from IPython.terminal.prompts import Prompts, Token
from IPython.terminal.embed import InteractiveShellEmbed


class PromptMain(Prompts):
    def __init__(self,string):
        self.text=string
    def setStr(self,string):
        self.text=string
    def in_prompt_tokens(self, cli=None):
        return [(Token, os.getcwd()+":\n"+' ['+self.text+'] '), (Token.Prompt, '<<< ')]
    def out_prompt_tokens(self,cli=None):
        return [(Token, ' ['+self.text+'] '), (Token.Prompt, '>>> ')]


#local_apk=1 -> In the future -> []
__prompx=PromptMain("..........")
__local_apk=0
__local_dex=0
def interact():
    ipshell = InteractiveShellEmbed()
    ipshell.prompts=__prompx
    ipshell()

def loadApk(path):
    global __local_apk
    global __local_dex
    print("Loading apk: "+path);
    __local_apk=APK(path)
    print("APK loaded");
    print("Reading DEX file...")
    vect=__local_apk.Dex()
    __local_dex=DexFile(vect[0])
    print("DEX loaded")
    __prompx.setStr(path.split('/')[-1]+" -- DEX 1/"+str(len(vect)))

def ApkFiles():
    l=__local_apk.FileList()
    for i in l:
        print ("File:\t"+i)
def ApkLib():
    l=__local_apk.FileList()
    for i in l:
        if(i.split('/')[0]=="lib"):
            print ("File:\t"+i)

def printDexHeader():
    __local_dex.printHeader()

#-StringList CHECK
def Strings(stringx=None):
    __local_dex.getString(stringx)

#-ClassList CHECK
def Classes(ind=None):
    __local_dex.getClass(ind)

#-MethodList CHECK
def Methods(ind=None):
    __local_dex.getMethod(ind)
#-TypeList CHECK
def Types(ind=None):
    __local_dex.getType(ind)

def Fields(ind=None):
    __local_dex.getField(ind)

def InfoString(ind):
    __local_dex.xString(ind)

def main():
	print ("APK Static Analyzer version 0")
#loadApk('../Uncrakable/UnCrackable-Level2.apk')
interact()

if __name__ == "__main__":
    main()


'''
#TODO
---Improve CLI interface
    1. Change help to help for this system
    2. Change PROMPT
---Adding new feature in APK
    1. HexEditor for other file in APK
    2. XML Reader
---DexFile
    1. ALL!
    - dex.String -> Override toString function; It will be good if I can print d.String
    - Internal Variable should begin with _
    - Method getString recheck
    - Refactor
    2. Support for dex 37 - 38
---Add new features
    - List of permission
    - List of API
    - permission <-> API method
    - Auto PT

---From DEX file we can export:
    -StringList CHECK
    -ClassList CHECK
    -MethodList CHECK
'''
