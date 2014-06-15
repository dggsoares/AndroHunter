from datetime import *

__author__ = 'dggsoares'


def date():
    #Date of the system
    today = datetime.now()
    return str(today.month) + '/' + str(today.day) + '/' + str(today.year)


def time():
    #Time of the system
    today = datetime.now()
    return str(today.hour) + ':' + str(today.minute) + ':' + str(today.second)


def system_date_time():
    aux = {}
    aux['data'] = date()
    aux['time'] = time()
    return aux


# Txt Methods
def write_head(txt_file):
    txt_file.write("    _              _           _   _             _              _   ___"
                   "\n   / \   _ __   __| |_ __ ___ | | | |_   _ _ __ | |_ ___ _ __  / | / _ \ "
                   "\n  / _ \ | '_ \ / _` | '__/ _ \| |_| | | | | '_ \| __/ _ \ '__| | || | | |"
                   "\n / ___ \| | | | (_| | | | (_) |  _  | |_| | | | | ||  __/ |    | || |_| |"
                   "\n/_/   \_\_| |_|\__,_|_|  \___/|_| |_|\__,_|_| |_|\__\___|_|    |_(_)___/ "
                   "\n\t\t\t\t\t--The final front-end for Androguard--"
                   "\n\t\t\tDate:" + date() + "                      Time: " + time() +
                   "\n<-------------------------------Txt Report------------------------------>")


def write_item(text, file):
    file.write('\n\t[.] ' + text.replace('_', ' ').title())


def write_content(content, file):
    if isinstance(content, list):
        if len(content) > 0:
            for item in content:
                file.write('\n\t\t-' + item)
        else:
            file.write('\n\t\t- No Records')
    elif isinstance(content, str):
        file.write('\n\t\t- ' + content)
    elif isinstance(content, dict):
        for category in content:
            file.write('\n\t\t[+] ' + category)
            for item in content.get(category):
                file.write('\n\t\t\t- ' + item)
    elif isinstance(content, unicode):
        file.write('\n\t\t- ' + content)
    else:
        file.write('\n\t\tNo Records')


def write_category(category, txt_file):
    txt_file.write('\n[+]------' + category.replace('_', ' ').title() + '------[+]')
