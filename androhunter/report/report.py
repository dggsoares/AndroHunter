#System imports
import os

#AndroHunter imports
from androhunter.util.util import *

#Jinja2 Import/Environment
from jinja2 import Environment, FileSystemLoader
TEMPLATE_PATH = 'template/template.html'

# Capture our current directory
THIS_DIR = os.path.dirname(os.path.abspath(__file__))

__author__ = 'dggsoares'


def create_report(dump, source, report_type):

    if report_type == "txt":
        print('[+] Creating TXT report...')
        report_name = dump['application_information']['file_name']+'.txt'
        path_file = './androhunter/report/'
        with open(path_file + report_name, 'w') as out_file:
            create_txt_report(dump, out_file)
        out_file.close()
        print('[+] Done! ' + report_name)
    elif report_type == "html":
        print('[+] Creating HTML report...')
        report_name = dump['application_information']['file_name']+'.html'
        system_date = system_date_time()
        create_html_report(dump, system_date, source)
        print('[+] Done! ' + report_name)


def create_txt_report(dump, txt_file):
    write_head(txt_file)
    for category in dump:
        write_category(category, txt_file)
        for item, content in dump.get(category).items():
            write_item(item, txt_file)
            write_content(content, txt_file)


def create_html_report(dump, system_date, source):
    report_name = dump['application_information']['file_name']+'.html'
    output_file = THIS_DIR+'/template/'+report_name
    env = Environment(loader=FileSystemLoader(THIS_DIR), trim_blocks=True)
    template = env.get_template(TEMPLATE_PATH)
    template.stream(data=dump, date=system_date, source=source).dump(output_file, encoding='utf-8')
