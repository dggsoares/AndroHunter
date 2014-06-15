#Global imports
import sys, argparse

# Androhunter imports
PATH_INSTALL = './'
sys.path.append(PATH_INSTALL)
from androhunter.core.core import *
from androhunter.core.analysis import *
from androhunter.report.report import *


def main(arguments):
    path_apk = arguments.file
    if path_apk:
        #Arguments
        online_interactions = arguments.online
        report_type = arguments.report
        graphic_generation = arguments.graphic

        #Analysis and Report
        a, d, dx = build_analyze_apk(path_apk)
        dump, source = analysis(a, d, dx, path_apk, online_interactions, graphic_generation)
        create_report(dump, source, report_type)
    else:
        print('[+] Especify the path for the APK file...')
        print('[+] -f <PATH_TO_APK>')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Analyze some Android Applications...')
    parser.add_argument('-f', '--file', type=str, help='Path to APK file')
    parser.add_argument('-o', '--online', type=int, default=0, help='<0-1> Disable or Enable online interactions')
    parser.add_argument('-r', '--report', type=str, default='html', help='<html, txt> Select the report output format')
    parser.add_argument('-g', '--graphic', type=str, default=1, help='<0-1> Disable or Enable CFG')
    args = parser.parse_args()
    main(args)