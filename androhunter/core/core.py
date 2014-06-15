__author__ = 'dggsoares'

#System imports
import sys

# Androguard imports
PATH_INSTALL = "./androguard/"
sys.path.append(PATH_INSTALL)
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *


def build_analyze_apk(path_apk):
    a = APK(path_apk)
    d = DalvikVMFormat(a.get_dex())
    dx = VMAnalysis(d)
    return a, d, dx