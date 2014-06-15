__author__ = 'dggsoares'

#AndroHunter imports
from androhunter.core.search import *


def analysis(a, d, dx, path_apk, online_interations, graphic_generation):
    print('[+] Analyzing application...')

    #Ordered dictionary
    dump = collections.OrderedDict()
    source = collections.OrderedDict()

    #Dicionarios auxiliaries
    ap = collections.OrderedDict()
    am = collections.OrderedDict()
    st = collections.OrderedDict()
    src = collections.OrderedDict()
    cert = collections.OrderedDict()

    #Dump analysis
    #Application Information
    ap['application_name'] = grab_application_name(a)
    ap['application_version'] = grab_application_version(a)
    ap['application_files'] = grab_files(a)
    ap['file_name'] = grab_filename(path_apk)
    ap['api_level'] = grab_sdk_version(a)
    ap['minimum_api_level'] = grab_min_sdk_version(a)
    ap['main_activity'] = grab_main_activity(a)
    ap['package_name'] = grab_package_name(a)
    ap['description'] = grab_description(a)
    ap['file_idenfication'] = grab_file_identification(path_apk)

    #VirusTotal API
    if online_interations:
        ap['antivirus_identification(powered_by_virustotal)'] = grab_virustotal(path_apk)

    #Certificate Information
    cert['certificate_information'] = grab_cert_information(path_apk)

    #AndroidManifest.xml
    am['permissions'] = grab_permissions(a)
    am['permissions_usage'] = grab_permissions_usage(dx)
    am['activities'] = grab_activies(a)
    am['services'] = grab_services(a)
    am['broadcast_receivers'] = grab_receivers(a)
    am['intents'] = grab_intents(a)

    #Strings
    st["url's"] = grab_urls(d)
    st["url's_usage"] = grab_urls_usage(d, dx, st["url's"])

    #Source Code
    src['classes'] = grab_source_code(d, dx)

    #Create Graphics Images
    if graphic_generation:
        grab_graphic_images(d, dx)

    dump['application_information'] = ap
    dump['certificate'] = cert
    dump['androidmanifest.xml'] = am
    dump['strings'] = st
    source['source_code'] = src

    return dump, source