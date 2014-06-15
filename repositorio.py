__author__ = 'dggsoares'

#Instrucoes no formato DEX
idx = 0
for instrucao in metodo.get_instructions():
    str = '\t\t' + '%x: ' %idx + instrucao.get_name() + instrucao.get_output()
    relatorio.write(str+'\n')
    idx += instrucao.get_length()

    #Java source code
    for metodo in classe.get_methods():
        relatorio.write('\t'+metodo.get_name()+'\n')

        method = dx.get_method(metodo)

        ms = decompile.DvMethod(method)
        ms.process()

        relatorio.write('\n\t\t'+ms.get_source())

    #Gerar arquivos PNG
    print('Gerando CFG dos metodos...')
    for classe in d.get_classes():
        for metodo in classe.get_methods():
            method2png(metodo.get_name(), dx.get_method(metodo))
            break
        break


strings = dx.get_tainted_variables().get_strings()
    for s, _ in strings:
        print(s)

for x in dump:
        print x
        for y, z in dump.get(x).items():
            print y, z

def gera_relatorio(path_apk, report, a, d, dx, gx):

    #Informacoes Gerais Ok
    report.write('\nInformacoes Gerais:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    filename = a.get_filename().split('/')[-1]
    report.write('Nome do Arquivo: ' + filename + '\n')
    report.write('Nome do Pacote: ' + a.get_package() + '\n')

    #MD5 OK
    md5 = hashlib.md5()
    with open(path_apk, 'rb') as afile:
        buf = afile.read()
        md5.update(buf)

    report.write('MD5: ' + md5.hexdigest() + '\n')

    #SHA1 OK
    sha1 = hashlib.sha1()
    with open(path_apk, 'rb') as afile:
        buf = afile.read()
        sha1.update(buf)

    report.write('SHA-1: ' + sha1.hexdigest() + '\n')

    #SHA256 OK
    sha256 = hashlib.sha256()
    with open(path_apk, 'rb') as afile:
        buf = afile.read()
        sha256.update(buf)

    report.write('SHA-256: ' + sha256.hexdigest() + '\n')

    report.write('Nivel de API: ' + a.get_min_sdk_version() + '\n')

    quebra_espaco(report, 20)
    report.write('\n')

    #Atividade Principal OK
    report.write('\nAtividade Principal:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    if a.get_main_activity() is not None:
        report.write(a.get_main_activity()+'\n')
    else:
        report.write('--Sem registros--\n')

    quebra_espaco(report, 20)

    #Funcionalidades
    report.write('\n\nFuncionalidades:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    if len(a.get_activities()) != 0:
        for atividades in a.get_activities():
            report.write(atividades+'\n')
    else:
        report.write('--Sem registros--\n')

    quebra_espaco(report, 20)

    #Permissoes
    report.write('\n\nPermissoes:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    for permissoes in a.get_permissions():
        report.write(permissoes+'\n')

    quebra_espaco(report, 20)

    #Servicos
    report.write('\n\nServicos:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    for servico in a.get_services():
        report.write(servico+'\n')

    quebra_espaco(report, 20)

    #Receiver
    report.write('\n\nBroadcast Receivers:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    for receiver in a.get_receivers():
        report.write(receiver+'\n')

    quebra_espaco(report, 20)

    #Intents
    report.write('\n\nIntents:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    for intent in a.get_intents():
        report.write(intent+'\n')

    quebra_espaco(report, 20)

    #Arquivos no APK
    report.write('\n\nArquivos no APK:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    for arquivos in a.get_files():
        report.write(arquivos+'\n')

    quebra_espaco(report, 20)

    #Classes
    report.write('\n\nClasses:\n')
    quebra_espaco(report, 20)
    report.write('\n')

    for classe in d.get_classes():
        report.write(classe.get_name()+'\n')

        for metodo in classe.get_methods():
            report.write('\t'+metodo.get_name()+'\n')

    quebra_espaco(report, 20)

def show_Path_Androhunter(vm, path):
    cm = vm.get_class_manager()

    if isinstance(path, PathVar) :
        dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
        info_var = path.get_var_info()
        return ("%s ---> %s->%s%s" % (info_var,
                                            dst_class_name,
                                            dst_method_name,
                                            dst_descriptor))
    else :
        if path.get_access_flag() == TAINTED_PACKAGE_CALL :
            src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
            dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )
            return ("%s->%s%s ---> %s->%s%s" % (src_class_name,
                                                        src_method_name,
                                                        src_descriptor,
                                                        dst_class_name,
                                                        dst_method_name,
                                                        dst_descriptor))
        else :
            src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
            return ("%s->%s%s" % (src_class_name,
                                        src_method_name,
                                        src_descriptor))

