__author__ = 'dggsoares'

#Virustotal Imports
from virustotal.virustotal import *

#Androguard Imports
from androhunter.core.search import *
from androguard.core.analysis.analysis import show_Path_Androhunter
from androguard.decompiler.dad import decompile
from androguard.core import bytecode

#System import
import hashlib
import collections
import subprocess


def grab_icon(a):
    #Grab icon of application
    return None


def grab_files(a):
    return a.get_files()


def grab_main_activity(a):
    #Grab Main activity
    if a.get_main_activity() is not None:
        return a.get_main_activity()
    else:
        return 'No records'


#FIXME
def grab_description(a):
    #Grab description
    return 'No Records'


#FIXME
def grab_application_name(a):
    return 'No Records'


def grab_application_version(a):
    version = a.get_androidversion_name()
    if version is not None:
        return version
    else:
        return 'No Records'


def grab_sdk_version(a):
    version = a.get_target_sdk_version()
    if version is not None:
        return version
    else:
        return 'No Records'


def grab_min_sdk_version(a):
    version = a.get_min_sdk_version()
    if version is not None:
        return version
    else:
        return 'No Records'


def grab_package_name(a):
    package = a.get_package()
    if package is not None:
        return package
    else:
        return 'No Records'


def grab_source_code(d, dx):
    source = collections.OrderedDict()

    for classe in d.get_classes():
        data = collections.OrderedDict()
        for metodo in classe.get_methods():
            method = dx.get_method(metodo)
            ms = decompile.DvMethod(method)
            ms.process()
            data[metodo.name] = ms.get_source()
        source[classe.get_name()] = data
    return source


def grab_filename(path_apk):
    return path_apk.split('/')[-1]


def grab_graphic_images(d, dx):
    path_images = './androhunter/report/template/'
    devnull = open('/dev/null', 'w')
    subprocess.call(['rm', '-rf', path_images+'cfg'])
    subprocess.call(['mkdir', path_images+'cfg'], stdout=devnull)
    print('[+] Creating CFG images...')

    for classe in d.get_classes():
        classe_name = classe.get_name().replace('/', '-').replace(';', '')
        print('\t[-] ' + classe_name + '...')
        subprocess.call(['mkdir', path_images + 'cfg/' + classe_name], stdout=devnull)
        for metodo in classe.get_methods():
            metodo_name = metodo.get_name().replace('<', '').replace('>', '')
            bytecode.method2png(path_images + 'cfg/' + classe_name + '/' + metodo_name + '.png', dx.get_method(metodo))


def grab_cert_information(path_apk):
    filename = grab_filename(path_apk)
    if filename.endswith('.apk'):
        new_filename = filename.replace('apk', 'zip')
        folder = './temp/'
        devnull = open('/dev/null', 'w')
        subprocess.call(['mkdir', 'temp'], stdout=devnull)
        subprocess.call(['cp', path_apk, folder+new_filename], stdout=devnull)
        subprocess.call(['unzip', folder+new_filename, '-d', folder], stdout=devnull)
        #dump = subprocess.check_output(['openssl', 'pkcs7', '-inform', 'DER', '-in', folder+'META-INF/CERT.RSA', '-noout','-print_certs', '-text'])
        dump = subprocess.check_output(['keytool', '-printcert', '-file', folder+'META-INF/CERT.RSA'])

        cert_information = collections.OrderedDict()
        data = []
        #Grab infos

        data.append(dump[dump.find('Owner'):dump.find('Issuer')].replace('Owner:', '').replace('\n', ''))
        cert_information['Owner'] = data
        data = []
        data.append(dump[dump.find('Issuer'):dump.find('Serial number')].replace('Issuer:', '').replace('\n', ''))
        cert_information['Issuer'] = data
        data = []
        data.append(dump[dump.find('Serial number'):dump.find('Valid from')].replace('Serial number:', '').replace('\n', ''))
        cert_information['Serial Number'] = data

        #Del temp dir
        subprocess.call(['rm', '-rf', './temp'])

        return cert_information
    else:
        return 'Only support .APK files'


def grab_md5(path_apk):
    #Return md5 of APK file
    md5 = hashlib.md5()
    with open(path_apk, 'rb') as afile:
        buf = afile.read()
        md5.update(buf)
    return md5.hexdigest()


def grab_sha1(path_apk):
    #Return sha1 of APK file
    sha1 = hashlib.sha1()
    with open(path_apk, 'rb') as afile:
        buf = afile.read()
        sha1.update(buf)
    return sha1.hexdigest()


def grab_sha256(path_apk):
    #Return sha256 of APK file
    sha256 = hashlib.sha256()
    with open(path_apk, 'rb') as afile:
        buf = afile.read()
        sha256.update(buf)
    return sha256.hexdigest()


def grab_permissions(a):
    permissions = []

    for permission in a.get_permissions():
        for perm in permission.split('.'):
            if perm.isupper():
                permissions.append(perm)
    return permissions


def grab_permissions_usage(dx):
    permissions = collections.OrderedDict()
    p = dx.get_permissions([])

    for i in p:
        data = []
        for j in p[i]:
            str_permissions = show_Path_Androhunter(dx.get_vm(), j)
            if str_permissions not in data:
                data.append(str_permissions)
        permissions[i] = data
    return permissions


def grab_activies(a):
    activities = a.get_activities()

    if len(activities) > 0:
        return activities
    else:
        return 'No records'


def grab_urls(d):
    strings = d.get_strings()
    url = []
    for item in strings:
        if item.find('http://') > -1 or item.find('https://') > -1:
            url.append(item)
    return url


def grab_services(a):
    services = a.get_services()
    if services is not None:
        return services
    else:
        return 'No Records'


def grab_receivers(a):
    receivers = a.get_receivers()
    if receivers is not None:
        return receivers
    else:
        return 'No Records'


def grab_intents(a):
    intents = a.get_intents()
    if intents is not None:
        return intents
    else:
        return 'No Records'


def grab_urls_usage(d, dx, p):
    usage = collections.OrderedDict()

    for url in p:
        z = dx.tainted_variables.get_string(url)
        usage[url] = z.show_paths_Androhunter(d)
    return usage


def grab_file_identification(path_apk):
    identification = collections.OrderedDict()
    data = []
    data.append(grab_md5(path_apk))
    identification['MD5'] = data
    data = []
    data.append(grab_sha256(path_apk))
    identification['SHA256'] = data
    data = []
    data.append(grab_sha1(path_apk))
    identification['SHA1'] = data
    return identification


def grab_virustotal(path_apk):
    print("[+] Grab Virustotal results...")
    detection = collections.OrderedDict()
    data = []
    api_key = '641e2a5d616063e15d56941a84d98c31492aae6574b829a0af057f07408994f8'
    v = VirusTotal(api_key)
    report = v.scan(path_apk)
    report.join()
    assert report.done is True
    data.append(str(report.total))
    detection['Antivirus Total'] = data
    data = []
    data.append(str(report.positives))
    detection['Antivirus Positive'] = data
    return detection