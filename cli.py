import sys

from optparse import OptionParser

from lib.apk import APK
from lib.decompiler import DexFile


from IPython.terminal.embed import InteractiveShellEmbed
from traitlets.config import Config


def interact():
    cfg = Config()
    ipshell = InteractiveShellEmbed(
        config=cfg,
        banner1="APK Static Analyzer version 0")
    ipshell()


def main():
	#print "APK Static Analyzer version 0"
	interact()


if __name__ == "__main__":
    main()