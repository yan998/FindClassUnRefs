# coding:utf-8
# 获取所有的类的ivars<属性>
import os
import re
import sys
import getopt


# 获取入参参数
def getInputParm():
    opts, args = getopt.getopt(sys.argv[1:], '-p:', ['path='])

    # 入参判断
    for opt_name, opt_value in opts:
        if opt_name in ('-p', '--path'):
            # 文件路径
            path = opt_value

    path = verified_app_path(path)
    return path


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


def get_all_class_ivars(path):
    print('获取项目中所有类的属性...')
    #         ivars          0x1000032e0 __OBJC_$_INSTANCE_VARIABLES_MyTableViewCell
    re_ivars_start = re.compile('\sivars\s*0x\w{9}\s*__OBJC_\$_INSTANCE_VARIABLES_(.+)')
    #  weakIvarLayout 0x0
    re_ivars_end = re.compile('\sweakIvarLayout\s0x0')
    re_ivar_name = re.compile('\s*name\s*0x\w{9}\s*_(.+)')
    re_ivar_type = re.compile('\s*type\s*0x\w{9}\s*@\"(.+)\"')
    imp_ivars_info = {}
    is_ivars_area = False

    # “otool - ov”将输出Objective - C类结构及其定义的方法。
    temp_array = []
    ivars_name = ''
    ivars_type = ''
    class_name = ''

    for line in os.popen("/usr/bin/otool -oV %s" % path).readlines():

        if re_ivars_start.findall(line):
            class_name = re_ivars_start.findall(line)[0]
            is_ivars_area = True
        if re_ivars_end.findall(line):
            is_ivars_area = False
        if is_ivars_area:
            # name
            if re_ivar_name.findall(line):
                ivars_name = re_ivar_name.findall(line)

            # type
            if re_ivar_type.findall(line):
                ivars_type = re_ivar_type.findall(line)

                # 防止为空，进行容错
                temp_ivars_type = 'id'
                if len(ivars_type) > 0:
                    temp_ivars_type = ivars_type[0]

                temp_ivars_name = 'XX'
                if len(ivars_name) > 0:
                    temp_ivars_name = ivars_name[0]

                dic = {"ivar_name": temp_ivars_name, "ivar_type": temp_ivars_type}
                temp_array.append(dic)

        else:

            if class_name and temp_array:
                imp_ivars_info[class_name] = list(temp_array)
                ivars_name = ''
                ivars_type = ''
                temp_array = []

    return imp_ivars_info


if __name__ == '__main__':
    path = getInputParm()
    # path = '/Users/a58/Library/Developer/Xcode/DerivedData/ClassUnRefDemo001-flxylfbdptrduxdpiaxpntqefjtq/Build/Products/Debug-iphonesimulator/ClassUnRefDemo001.app/ClassUnRefDemo001'
    imp_ivars_info = get_all_class_ivars(path)
    # print(imp_ivars_info)
