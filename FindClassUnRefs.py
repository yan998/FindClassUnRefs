# coding:utf-8
# 查找iOS项目无用类脚本

import os
import re
import sys
import getopt
import FindAllClassIvars

# 获取入参参数
def getInputParm():
    opts, args = getopt.getopt(sys.argv[1:], '-p:-b:-w:', ['path=', 'blackListStr', 'whiteListStr'])

    blackListStr = ''
    whiteListStr = ''
    whiteList = []
    blackList = []
    # 入参判断
    for opt_name, opt_value in opts:
        if opt_name in ('-p', '--path'):
            # 文件路径
            path = opt_value
        if opt_name in ('-b', '--blackListStr'):
            # 检测黑名单前缀，不检测谁
            blackListStr = opt_value
        if opt_name in ('-w', '--whiteListStr'):
            # 检测白名单前缀，只检测谁
            whiteListStr = opt_value

    if len(blackListStr) > 0:
        blackList = blackListStr.split(",")

    if len(whiteListStr) > 0:
        whiteList = whiteListStr.split(",")

    if len(whiteList) > 0 and len(blackList) > 0:
        print("\033[0;31;40m白名单【-w】和黑名单【-b】不能同时存在\033[0m")
        exit(1)

    # 判断文件路径存不存在
    if not os.path.exists(path):
        print("\033[0;31;40m输入的文件路径不存在\033[0m")
        exit(1)

    return path, blackList, whiteList


def verified_app_path(path):
    if path.endswith('.app'):
        appname = path.split('/')[-1].split('.')[0]
        path = os.path.join(path, appname)
        if appname.endswith('-iPad'):
            path = path.replace(appname, appname[:-5])
    if not os.path.isfile(path):
        return None
    if not os.popen('file -b ' + path).read().startswith('Mach-O'):
        return None
    return path


def pointers_from_binary(line, binary_file_arch):
    if len(line) < 16:
        return None
    line = line[16:].strip().split(' ')
    pointers = set()
    if binary_file_arch == 'x86_64':
        # untreated line example:00000001030cec80	d8 75 15 03 01 00 00 00 68 77 15 03 01 00 00 00
        if len(line) >= 8:
            pointers.add(''.join(line[4:8][::-1] + line[0:4][::-1]))
        if len(line) >= 16:
            pointers.add(''.join(line[12:16][::-1] + line[8:12][::-1]))
        return pointers
    # arm64 confirmed,armv7 arm7s unconfirmed
    if binary_file_arch.startswith('arm'):
        # untreated line example:00000001030bcd20	03138580 00000001 03138878 00000001
        if len(line) >= 2:
            pointers.add(line[1] + line[0])
        if len(line) >= 4:
            pointers.add(line[3] + line[2])
        return pointers
    return None


def class_ref_pointers(path, binary_file_arch):
    print('获取项目中所有被引用的类...')
    ref_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classrefs %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        ref_pointers = ref_pointers.union(pointers)
    if len(ref_pointers) == 0:
        exit('Error:class ref pointers null')
    return ref_pointers


def class_list_pointers(path, binary_file_arch):
    print('获取项目中所有的类...')
    list_pointers = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_classlist %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        list_pointers = list_pointers.union(pointers)
    if len(list_pointers) == 0:
        exit('Error:class list pointers null')
    return list_pointers


def filter_use_load_class(path, binary_file_arch):
    print('获取项目中所有使用load方法的类...')
    list_load_class = set()
    lines = os.popen('/usr/bin/otool -v -s __DATA __objc_nlclslist %s' % path).readlines()
    for line in lines:
        pointers = pointers_from_binary(line, binary_file_arch)
        if not pointers:
            continue
        list_load_class = list_load_class.union(pointers)
    return list_load_class


# 通过符号表中的符号，找到对应的类名
def class_symbols(path):
    print('通过符号表中的符号，获取类名...')
    symbols = {}
    # class symbol format from nm: 0000000103113f68 (__DATA,__objc_data) external _OBJC_CLASS_$_TTEpisodeStatusDetailItemView
    re_class_name = re.compile('(\w{16}) .* _OBJC_CLASS_\$_(.+)')
    lines = os.popen('nm -nm %s' % path).readlines()
    for line in lines:
        result = re_class_name.findall(line)
        if result:
            (address, symbol) = result[0]
            # print(result)
            symbols[address] = symbol
    if len(symbols) == 0:
        exit('Error:class symbols null')
    return symbols


def filter_super_class(unref_symbols):
    re_subclass_name = re.compile("\w{16} 0x\w{9} _OBJC_CLASS_\$_(.+)")
    re_superclass_name = re.compile("\s*superclass 0x\w* _OBJC_CLASS_\$_(.+)")
    # subclass example: 0000000102bd8070 0x103113f68 _OBJC_CLASS_$_TTEpisodeStatusDetailItemView
    # superclass example: superclass 0x10313bb80 _OBJC_CLASS_$_TTBaseControl
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()
    subclass_name = ""
    superclass_name = ""
    for line in lines:
        subclass_match_result = re_subclass_name.findall(line)
        if subclass_match_result:
            subclass_name = subclass_match_result[0]
            superclass_name = ''
        superclass_match_result = re_superclass_name.findall(line)
        if superclass_match_result:
            superclass_name = superclass_match_result[0]


        # 查看所有类的父类子类关系
        # if len(subclass_name) > 0 and len(superclass_name) > 0:
        #     # print("当前找到了superclass == " + line)
        #     print("superclass:%s  subClass:%s" % (superclass_name, subclass_name))

        if len(subclass_name) > 0 and len(superclass_name) > 0:
            if superclass_name in unref_symbols and subclass_name not in unref_symbols:
                # print("删除的父类 -- %s   %s" % (superclass_name, subclass_name))
                unref_symbols.remove(superclass_name)
            superclass_name = ''
            subclass_name = ''
    return unref_symbols


def class_unref_symbols(path):
    # binary_file_arch: distinguish Big-Endian and Little-Endian
    # file -b output example: Mach-O 64-bit executable arm64
    binary_file_arch = os.popen('file -b ' + path).read().split(' ')[-1].strip()

    print("*****" + binary_file_arch)

    # 被使用的类和有load方法的类取合集，然后和所有的类的集合取差集
    unref_pointers = class_list_pointers(path, binary_file_arch) - (
            class_ref_pointers(path, binary_file_arch) | filter_use_load_class(path, binary_file_arch))

    if len(unref_pointers) == 0:
        exit('木有找到未使用的类')
    # 通过符号找类名
    symbols = class_symbols(path)

    # ###### 测试 ######
    # print("所有的类列表")
    # all_class_list = find_class_list(class_list_pointers(path, binary_file_arch), symbols)
    # print(all_class_list)
    #
    # print("\n所有的被引用的类列表")
    # all_class_ref_list = find_class_list(class_ref_pointers(path, binary_file_arch), symbols)
    # print(all_class_ref_list)
    #
    # print("\n所有的有load方法的类的列表")
    # all_class_load_list = find_class_list(filter_use_load_class(path, binary_file_arch), symbols)
    # print(all_class_load_list)
    # ###### 测试 ######

    unref_symbols = set()
    for unref_pointer in unref_pointers:
        if unref_pointer in symbols:
            unref_symbol = symbols[unref_pointer]
            unref_symbols.add(unref_symbol)
    if len(unref_symbols) == 0:
        exit('Finish:class unref null')

    return unref_symbols


def find_class_list(unref_pointers, symbols):
    unref_symbols = set()
    for unref_pointer in unref_pointers:
        if unref_pointer in symbols:
            unref_symbol = symbols[unref_pointer]
            unref_symbols.add(unref_symbol)
    if len(unref_symbols) == 0:
        exit('Finish:class unref null')

    return unref_symbols


# 检测通过runtime的形式，类使用字符串的形式进行调用,如果查到，可以认为用过
def filter_use_string_class(path, unref_symbols):
    str_class_name = re.compile("\w{16}  (.+)")
    # 获取项目中所有的字符串 @"JRClass"
    lines = os.popen('/usr/bin/otool -v -s __TEXT __cstring %s' % path).readlines()

    for line in lines:

        stringArray = str_class_name.findall(line)
        if len(stringArray) > 0:
            tempStr = stringArray[0]
            if tempStr in unref_symbols:
                unref_symbols.remove(tempStr)
                continue
    return unref_symbols


# 查找所有的未使用到的类，是否出现在了相关类的属性中
# 自己作为自己的属性不算
def find_ivars_is_unuse_class(path, unref_sels):
    # {'MyTableViewCell':
    # [{'ivar_name': 'superModel', 'ivar_type': 'SuperModel'}, {'ivar_name': 'showViewA', 'ivar_type': 'ShowViewA'}, {'ivar_name': 'dataSource111', 'ivar_type': 'NSArray'}],
    # 'AppDelegate': [{'ivar_name': 'window', 'ivar_type': 'UIWindow'}]}
    imp_ivars_info = FindAllClassIvars.get_all_class_ivars(path)
    temp_list = list(unref_sels)
    find_ivars_class_list = []
    for unuse_class in temp_list:
        for key in imp_ivars_info.keys():
            # 当前类包含自己类型的属性不做校验
            if key == unuse_class:
                continue
            else:
                ivars_list = imp_ivars_info[key]
                is_find = 0
                for ivar in ivars_list:
                    if unuse_class == ivar["ivar_type"]:
                        unref_symbols.remove(unuse_class)
                        find_ivars_class_list.append(unuse_class)
                        is_find = 1
                        break
                if is_find == 1:
                    break

    return unref_symbols, find_ivars_class_list


def filter_category_use_load_class(path, unref_symbols):
    re_load_category_class = re.compile("\s*imp\s*0x\w*\s*[+|-]\[(.+)\(\w*\) load\]")
    lines = os.popen("/usr/bin/otool -oV %s" % path).readlines()

    for line in lines:
        load_category_match_result = re_load_category_class.findall(line)
        if len(load_category_match_result) > 0:
            re_load_category_class_name = load_category_match_result[0]
            if re_load_category_class_name in unref_symbols:
                unref_symbols.remove(re_load_category_class_name)
    return unref_symbols

# 黑白名单过滤
def filtration_list(unref_symbols, blackList, whiteList):
    # 数组拷贝
    temp_unref_symbols = list(unref_symbols)
    if len(blackList) > 0:
        # 如果黑名单存在，那么将在黑名单中的前缀都过滤掉
        for unrefSymbol in temp_unref_symbols:
            for blackPrefix in blackList:
                if unrefSymbol.startswith(blackPrefix) and unrefSymbol in unref_symbols:
                    unref_symbols.remove(unrefSymbol)
                    break

    # 数组拷贝
    temp_array = []
    if len(whiteList) > 0:
        # 如果白名单存在，只留下白名单中的部分
        for unrefSymbol in unref_symbols:
            for whitePrefix in whiteList:
                if unrefSymbol.startswith(whitePrefix):
                    temp_array.append(unrefSymbol)
                    break
        unref_symbols = temp_array

    return unref_symbols


def write_to_file(unref_symbols, find_ivars_class_list):
    script_path = sys.path[0].strip()
    file_name = 'find_class_unRefs.txt'
    f = open(script_path + '/' + file_name, 'w')
    f.write('查找到未使用的类: %d个,【请在项目中二次确认无误后再进行相关操作】\n' % len(unref_symbols))

    num = 1
    if len(find_ivars_class_list):
        show_title = "未被使用的类列表中 -- 出现在已使用类的属性中的类 --------"
        print(show_title)
        f.write(show_title + "\n")
        for name in find_ivars_class_list:
            find_ivars_class_str = ("%d : %s" % (num, name))
            print(find_ivars_class_str)
            f.write(find_ivars_class_str + "\n")
            num = num + 1

    num = 1
    print("\n")
    for unref_symbol in unref_symbols:
        showStr = ('%d : %s' % (num, unref_symbol))
        print(showStr)
        f.write(showStr + "\n")
        num = num + 1
    f.close()

    print('未使用到的类查询完毕，结果已保存在了%s中，【请在项目中二次确认无误后再进行相关操作】' % file_name)


if __name__ == '__main__':

    path, blackList, whiteList = getInputParm()

    path = verified_app_path(path)
    if not path:
        sys.exit('Error:invalid app path')

    # 查找未使用类结果
    unref_symbols = class_unref_symbols(path)

    # 检测通过runtime的形式，类使用字符串的形式进行调用,如果查到，可以认为用过
    unref_symbols = filter_use_string_class(path, unref_symbols)

    # 查找当前未被引用的子类
    unref_symbols = filter_super_class(unref_symbols)

    # 检测当前类的分类中是否有load方法，如果有，认为是被引用的类
    unref_symbols = filter_category_use_load_class(path, unref_symbols)

    # 黑白名单过滤
    unref_symbols = filtration_list(unref_symbols, blackList, whiteList)

    # 过滤属性，看当前查找到的未使用类，是否在使用的类的属性中
    unref_symbols, find_ivars_class_list = find_ivars_is_unuse_class(path, unref_symbols)

    # 整理结果，写入文件
    write_to_file(unref_symbols, find_ivars_class_list);
