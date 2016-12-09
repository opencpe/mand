''' This is a pyang plugin for generating the open-cpe c struct data model from yang files. '''

import optparse
import sys
import re
import string

from pyang import plugin
from pyang import statements

from copy import deepcopy

def pyang_plugin_init():
    plugin.register_plugin(TreePlugin())

class TreePlugin(plugin.PyangPlugin):
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['OpenCPE'] = self

    def setup_ctx(self, ctx):
        if ctx.opts.tree_help:
            print_help()
            sys.exit(0)

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):

        fd = open('p_table.c', 'w')
        make_license(fd)
        fd.write("#include <stdlib.h>\n")
        fd.write("#include <limits.h>\n")
        fd.write("#include \"dm.h\"\n")
        fd.write("#include \"dm_token.h\"\n")
        fd.write("#include \"dm_action.h\"\n")
        fd.write("#include \"p_table.h\"\n")

        emit_tree(modules, fd)

        top_elements = []
        for module in modules:
            for child in module.substmts:
                if child.keyword in ['container', 'list', 'leaf', 'leaf-list']:
                    top_elements.append(child)

        # the root, hardcoded with top_elements
        fd.write("const struct dm_table dm_root =\n")
        fd.write("{\n")
        fd.write(tab + "TABLE_NAME(\".\")\n")
        fd.write(tab + ".size   = " + str(len(top_elements)) + ",\n")
        fd.write(tab + ".table  =\n")
        fd.write(tab + "{\n")
        for element in top_elements:
            fd.write(2*tab + "{\n")
            fd.write(3*tab + "/* " + str(top_elements.index(element)+1) +" */\n")
            fd.write(3*tab + ".key    = \"" + make_key(element, keep_hyphens=True) + "\",\n")
            fd.write(3*tab + ".flags  = F_READ | F_WRITE,\n")
            fd.write(3*tab + ".action = DM_NONE,\n")
            fd.write(3*tab + ".type   = T_TOKEN,\n")
            fd.write(3*tab + ".u.t = {\n")
            fd.write(4*tab + ".table  = &" + make_name(element) + ",\n")
            fd.write(4*tab + ".max    = INT_MAX,\n")
            fd.write(3*tab + "},\n")
            fd.write(2*tab + "},\n")
        fd.write(tab + "}\n")
        fd.write("};\n")

        header_collector.insert(0, "#define dm__system 1\n")
        header_collector.insert(0, "#ifndef __P_TABLE_H\n" + "#define __P_TABLE_H\n\n\n")
        header_collector.append("\n\n#endif")


def emit_tree(modules, fd):

    typedefs = {}
    for module in modules:
        module_typedefs = module.search('typedef')
        for typedef in module_typedefs:
            typedefs[typedef.i_module.i_prefix + ':' + typedef.arg] = typedef

    groupings = {}
    for module in modules:
        module_groupings = module.search('grouping')
        for grouping in module_groupings:
            groupings[grouping.i_module.i_prefix + ':' + grouping.arg] = grouping

    augments = {}
    for module in modules:
        module_augments = module.search('augment')
        for augment in module_augments:
            if augment.arg not in augments.keys():
                augments[augment.arg] = [augment]
            else:
                augments[augment.arg] += [augment]

    deviations = {}
    for module in modules:
        module_deviations = module.search('deviation')
        for deviation in module_deviations:
            deviations[deviation.arg] = deviation

    annotations = {}
    for module in modules:
        module_annotations = module.search(('opencpe-annotations', 'annotate'))
        for annotation in module_annotations:
            annotations[annotation.arg] = annotation

    actions = []
    #action-fields will be collected from everywhere, but should be positioned in the ocpe-actiontable.yang file
    for module in modules:
        module_actions = module.search(('opencpe-actiontable', 'action-field'))
        actions += module_actions


    # MAIN LOOP
    for module in modules:

        chs = [ch for ch in module.i_children
               if ch.keyword in statements.data_definition_keywords]

        if len(chs) > 0:
            print_children(chs, module, typedefs, groupings, augments, deviations, annotations, fd)

    #now write the header file
    fd = open('p_table.h', 'w')
    make_license(fd)
    fd.write("""
#ifndef __P_TABLE_H
#define __P_TABLE_H

#define dm__system 1
\n""")
    for newLine in header_collector:
        fd.write( newLine )
    fd.write("\n\n#endif\n")

    # generate the action table
    fd = open('dm_action_table.c', 'w')
    generate_action_table(actions, fd)
    fd = open('dm_action_table.h', 'w')
    generate_action_table_header(actions, fd)

    # generate the debug table
    fd = open('dm_action_debug.c', 'w')
    generate_debug_table(actions, fd)


#GLOBAL SETTINGS
#mapping of the yang types to c types
c_types = {'string':'T_STR', 'enumeration':'T_ENUM', 'uint8':'T_UINT', 'uint16':'T_UINT', 'uint32':'T_UINT', 'uint64':'T_UINT64',
           'int8':'T_INT', 'int16':'T_INT', 'int32':'T_INT', 'int64':'T_INT64', 'boolean':'T_BOOL', 'bits':'T_BINARY',
           'binary':'T_BASE64', 'identityref':'T_STR', 'leafref':'T_SELECTOR', 'inet:ipv4-address':'T_IPADDR4', 'inet:ipv6-address':'T_IPADDR6',
            'empty':'T_BOOL', 'inet:host':'T_STR', 'inet:ip-address':'T_STR', 'yang:date-and-time':'T_TICKS'}

#this dict states which types in the yang model are directly supported in the c model
builtin_types = ['binary', 'bits', 'boolean', 'decimal64', 'empty', 'enumeration',
                  'identityref', 'instance-identifier', 'int8', 'int16', 'int32',
                    'int64', 'leafref', 'string', 'uint8', 'uint16', 'uint32', 'uint64', 'union',
                        'inet:ipv4-address', 'inet:ipv6-address', 'inet:ip-address', 'inet:host', 'yang:date-and-time']

#used to collect the information for p_table.h
header_collector = []

#formatting
tabsize = 4
tab = tabsize * " "


def get_write_access(parent_write_access, child):
    child_write_access = child.search_one('config')
    if child_write_access != None:
        child_write_access = child_write_access.arg
    # yang differentiates between 'config true'
    # and 'config false' for giving write access (or not).
    # Default is 'config true'.
    if child_write_access == 'false' or parent_write_access == False:
        child_write_access = False
    else:
        child_write_access = True
    return child_write_access


def print_children(i_children, module, typedefs, groupings, augments, deviations, annotations, fd, write_access=True):

    for ch in i_children:
        if ((ch.arg == 'input' or ch.arg == 'output') and
            ch.parent.keyword == 'rpc' and
            len(ch.i_children) == 0 and
            ch.parent.search_one(ch.arg) is None):
            pass
        #exclude the deviations with 'not supported'
        elif get_xpath(ch) not in deviations.keys():
            child_write_access = get_write_access(write_access, ch)
            print_node(ch, module, typedefs, groupings, augments, deviations, annotations, fd, child_write_access)

def print_node(s, module, typedefs, groupings, augments, deviations, annotations, fd, write_access):
    name = make_name(s)

    if hasattr(s, 'i_children'):
        chs = s.i_children
        print_children(chs, module, typedefs, groupings, augments, deviations, annotations, fd, write_access)

    if s.keyword in ['container', 'list', 'leaf-list']:

        children = s.substmts

        #include the augments if neccassary
        if get_xpath(s) in augments.keys():
            for augment in augments[get_xpath(s)]:
                children += augment.i_children

        keys = None
        if s.keyword in ['list', 'leaf-list']:
            keys = s.search('key')
            key_leafs = {}
            for key in keys:
                for leaf in s.search('leaf'):
                    if leaf.arg == key.arg:
                        type = seek_type(leaf.search_one('type'), leaf, builtin_types, typedefs)
                        key_leafs[key.arg] = type.arg

            fd.write("const struct index_definition " + "index_" + name + " =\n")
            fd.write("{\n")
            fd.write(tab + ".idx = {\n")
            fd.write(2*tab + "{ .flags = IDX_UNIQUE, .type = T_INSTANCE },\n")
            for key in keys:
                fd.write(2*tab + "{ .flags = IDX_UNIQUE, .type = " + c_types[key_leafs[key.arg]] +
                         ", .element = " + "field_" + name + "_" + make_key(key, keep_hyphens=False) + " },\n")
            fd.write(tab + "},\n")
            fd.write(tab + ".size = " + str(len(keys)+1) + "\n")
            fd.write("};\n")
            fd.write("\n")


        fd.write("const struct dm_table " + name + " =\n")
        fd.write("{\n")
        fd.write(tab + "TABLE_NAME(\"" + make_name(s, multi_instance=True) + "\")\n" )

        if s.keyword in ['list', 'leaf-list']:
            fd.write(tab + ".index = " + "&index_" + name + ",\n")

        fd.write(tab + ".table =\n")
        fd.write(tab + "{\n")

        counter = 1
        if s.keyword == 'leaf-list':
            counter = print_field(fd, s, typedefs, annotations, -1, keys, write_access=write_access) + 1


        #the inner part of one struct
        for child in children:
            if child.keyword in ['container', 'list', 'leaf', 'leaf-list'] and get_xpath(child) not in deviations.keys():
                counter += print_field(fd, child, typedefs, annotations, counter, keys, write_access=get_write_access(write_access, child))
            elif child.keyword == 'choice':
                for substmt in child.substmts:
                    if substmt.keyword in ['container', 'list', 'leaf', 'leaf-list']:
                        counter += print_field(fd, substmt, typedefs, annotations, counter, keys, write_access=get_write_access(write_access, child))
                cases = child.search('case')
                for case in cases:
                    for substmt in case.substmts:
                        if substmt.keyword in ['container', 'list', 'leaf', 'leaf-list']:
                            counter += print_field(fd, substmt, typedefs, annotations, counter, keys, write_access=get_write_access(write_access, child))
            elif child.keyword == 'uses':
                grouping = groupings[child.i_module.i_prefix + ':' + child.arg]
                for groupchild in grouping.substmts:
                    if groupchild.keyword in ['container', 'list', 'leaf', 'leaf-list', 'choice']:
                        counter += print_field(fd, groupchild, typedefs, annotations, counter, keys, prefix=make_name(s)+'__', write_access=get_write_access(write_access, child))


        fd.write(tab + "},\n")
        fd.write(tab + ".size = " + str(counter-1) + "\n")
        fd.write("};\n")
        fd.write("\n")

    elif s.keyword in ['leaf']:
        return

    fd.write('\n')

def collect_unions(type, child, builtin_types, typedefs):
    new_types = type.search('type')
    if new_types == []:
        return []
    types = []
    for new_type in new_types:
        new_real_type = seek_type(new_type, child, builtin_types, typedefs)
        if new_real_type.arg == 'union':
            types += collect_unions(new_real_type, child, builtin_types, typedefs)
        else:
            types.append(new_type)
    return types

def print_field(fd, child, typedefs, annotations, counter, keys, prefix='', write_access=True):

    #include the annotations if neccassary
    action = None
    flags = ['F_READ']
    if keys != None:
        for key in keys:
            if child.arg == key.arg:
                flags.append('F_INDEX')
    getter = False
    setter = False
    annotated_type = None
    if get_xpath(child) in annotations.keys():
        action = annotations[get_xpath(child)].search_one(('opencpe-annotations', 'action'))
        annotated_flags = annotations[get_xpath(child)].search_one(('opencpe-annotations', 'flags'))
        getter = annotations[get_xpath(child)].search_one(('opencpe-annotations', 'getter'))
        setter = annotations[get_xpath(child)].search_one(('opencpe-annotations', 'setter'))
        annotated_type = annotations[get_xpath(child)].search_one(('opencpe-annotations', 'type'))
        if action != None:
            action = action.arg.upper()
        if annotated_flags != None:
            flags.extend(annotated_flags.arg.upper().split(';'))
        if getter != None and getter.arg == 'true':
            getter = True
        if setter != None and setter.arg == 'true':
            setter = True
        if annotated_type != None:
            annotated_type = annotated_type.arg.upper()

    # set additional flags
    if write_access == True:
        flags.append('F_WRITE')
    if getter:
        flags.append('F_GET')
    if setter:
        flags.append('F_SET')
    # set write and array flag for leaf lists
    if counter == -1 or child.keyword == 'leaf-list':
        flags.append('F_ARRAY')

    field_counter = 1
    #-1 for leaf-list
    if child.keyword in ['leaf'] or counter == -1:

        type =  seek_type(child.search_one('type'), child, builtin_types, typedefs)

        key = ''
        counter = abs(counter)
        types = [type]

        union_flag = False
        if type.arg == 'union':
            types = collect_unions(type, child, builtin_types, typedefs)
            field_counter = len(types)
            union_flag = True

        for i in range(field_counter):

            type_i = types[i]

            # set additional flags
            if type_i.arg == 'yang:date-and-time':
                flags.append('F_DATETIME')
            flags = list(set(flags))    # remove duplicates

            type = seek_type(type_i, child, builtin_types, typedefs)
            if union_flag:
                header_key = make_key(type_i, child.arg + '_', keep_hyphens=False)
                hyphen_key = make_key(type_i, child.arg + '_', keep_hyphens=True)
            elif child.keyword == 'leaf-list':
                header_key = ''.join(child.arg.split('-')) + "_" + make_key(child, keep_hyphens=False)
                hyphen_key = make_key(child, keep_hyphens=True)
            else:
                header_key = make_key(child, keep_hyphens=False)
                hyphen_key = make_key(child, keep_hyphens=True)

            name = make_name(child.parent)
            header_collector.insert(0, "#define " + "field_" + name + "_" + header_key + " " + str(counter) + "\n")

            fd.write(2*tab + "{\n")
            fd.write(3*tab + "/* " + str(counter) + " */\n")
            fd.write(3*tab + ".key = " + "\"" + hyphen_key + "\"" + ",\n")

            fd.write(3*tab + ".flags = ")
            for flag in flags[:-1]:
                fd.write(flag + " | ")
            fd.write(flags[-1] + ",\n")

            if action == None:
                fd.write(3*tab + ".action = DM_NONE" + ",\n")
            else:
                fd.write(3*tab + ".action = " + action + ",\n")
            counter += 1

            if getter or setter:
                fd.write(3*tab + ".fkts.value = {\n")
                if getter:
                    fd.write(4*tab + ".get = get_" + name + "_" + header_key + ",\n")
                    header_collector.insert(0, "DM_VALUE get_" + name + "_" + header_key + "(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE);\n")
                if setter:
                    fd.write(4*tab + ".set = set_" + name + "_" + header_key + ",\n")
                    header_collector.insert(0, "int set_" + name + "_" + header_key + "(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE *, DM_VALUE);\n")
                fd.write(3*tab + "},\n")

            if annotated_type != None:
                fd.write(3*tab + ".type = " + annotated_type + ",\n")
            #for yang standard types
            elif type.arg == 'enumeration':
                print_type(fd, type, "field_" + name + "_" + header_key + "_")
            else:
                print_type(fd, type)

            fd.write(2*tab + "},\n")

    else:
        name = make_name(child.parent)
        header_collector.insert(0, "#define " + "field_" + name + "_" + make_key(child) + " " + str(counter) + "\n")

        fd.write(2*tab + "{\n")
        fd.write(3*tab + "/* " + str(abs(counter)) + " */\n")
        fd.write(3*tab + ".key = " + "\"" + make_key(child, keep_hyphens=True) + "\"" + ",\n")

        flags = list(set(flags))    # remove duplicates
        fd.write(3*tab + ".flags = ")
        for flag in flags[:-1]:
            fd.write(flag + " | ")
        fd.write(flags[-1] + ",\n")

        if action == None:
            fd.write(3*tab + ".action = DM_NONE" + ",\n")
        else:
            fd.write(3*tab + ".action = " + action + ",\n")

        if getter or setter:
            fd.write(3*tab + ".fkts.value = {\n")
            if getter:
                fd.write(4*tab + ".get = get_" + hyphen_key + ",\n")
                header_collector.insert(0, "DM_VALUE get_" + name + "_" + header_key + "(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE);\n")
            if setter:
                fd.write(4*tab + ".set = set_" + hyphen_key + ",\n")
                header_collector.insert(0, "DM_VALUE set_" + name + "_" + header_key + "(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE);\n")
            fd.write(3*tab + "},\n")

        c_type = ''
        if child.keyword in ['leaf-list', 'list']:
            c_type = 'T_OBJECT'
        else:
            c_type = 'T_TOKEN'
        fd.write(3*tab + ".type = " + c_type  + ",\n")
        fd.write(3*tab + ".u.t = {\n")
        fd.write(4*tab + ".table = " + "&" + prefix + make_name(child) + ",\n")
        if c_type == 'T_OBJECT':
            fd.write(4*tab + ".max = INT_MAX,\n")
        fd.write(3*tab + "},\n")
        fd.write(2*tab + "},\n")

    return field_counter


def print_type(fd, type, parentname = ''):

    fd.write(3*tab + ".type = " + c_types[type.arg] + ",\n")

    if type.arg == 'enumeration':
        enumeration = type
        enums = enumeration.search('enum')
        fd.write(3*tab + ".u.e = { .cnt =" + str(len(enums)) + ", .data = ")
        fd.write("\"")
        header_typedef = "typedef enum {\n"
        for enum in enums[0:-1]:
            fd.write(enum.arg + "\\000")
            header_typedef += tab + parentname + make_key(enum) + ",\n"
        fd.write(enums[-1].arg + "\" }\n")
        header_typedef += tab + parentname + make_key(enums[-1]) + ",\n}" + parentname + "e;" + "\n"
        header_collector.insert(0, header_typedef)

    if type.arg == 'string':
        string = type
        length = string.search_one('length')
        if length != None:
            min = 0
            max = 0
            for i in range(len(length.arg)):
                if length.arg[i] == '.':
                    min = length.arg[0:i]
                    max = length.arg[i+2:]
                    if min == 'min':
                        min = 'INT_MIN'
                    if max == 'max':
                        max = 'INT_MAX'
                    break
            if i == len(length.arg)-1:
                min = length.arg
                fd.write(3*tab + ".u.l = {\n" + 4*tab + ".min = " + min + ",\n" )
                fd.write(3*tab + "},\n")
            else:
                fd.write(3*tab + ".u.l = {\n" + 4*tab + ".min = " + min + ",\n" + 4*tab + ".max = " + max + ",\n" )
                fd.write(3*tab + "},\n")

    if type.arg[0:3] == 'int' or type.arg[0:4] == 'uint':
        integer = type
        integer_range = integer.search_one('range')
        if integer_range != None:
            min = 0
            max = 0
            for i in range(len(integer_range.arg)):
                if integer_range.arg[i] == '.':
                    min = integer_range.arg[0:i]
                    max = integer_range.arg[i+2:]
                    if min == 'min':
                        min = 'INT_MIN'
                    if max == 'max':
                        max = 'INT_MAX'
                    break
            fd.write(3*tab + ".u.l = {\n" + 4*tab + ".min = " + min + ",\n" + 4*tab + ".max = " + max + ",\n" )
            fd.write(3*tab + "},\n")

#helpers
def get_typename(s):
    t = s.search_one('type')
    if t is not None:
        return t.arg
    else:
        return ''

def make_name(s, multi_instance=False):
    xpath = make_path_string(s, multi_instance=multi_instance)
    name = ""
    for i in range(1, len(xpath)):
        if xpath[i] == '/':
            name += '__'
        elif xpath[i] == '-':
            name += '_'
        else:
            name += xpath[i]
    return name

def make_key(s, prefix='', keep_hyphens=False):
    arg = s.arg

    # this should only apply to unions which are dissolved
    if ':' in arg:
        arg = arg.split(':')[-1]

    with_hyphens = prefix + arg
    key = ''
    for i in range(len(with_hyphens)):
        if with_hyphens[i] == '-' and not keep_hyphens:
            continue
        elif with_hyphens[i] == '/':
            key += '__'
        else:
            key += with_hyphens[i]
    return key

def make_path_string(s, with_prefixes=False, multi_instance=False):
    suffix = ''
    if multi_instance:
        if s.keyword in ['list', 'leaf-list']:
            suffix = ".{i}"
    if s.keyword in ['choice', 'case']:
           return make_path_string(s.parent, with_prefixes, multi_instance)
    def name(s):
        if with_prefixes:
            return s.i_module.i_prefix + "_" + s.arg
        else:
            return s.arg
    if s.parent.keyword in ['module', 'submodule']:
        return "/ocpe/" + name(s) + suffix
    elif s.parent.keyword in ['grouping']:
        return "/" + name(s) + suffix
    else:
        p = make_path_string(s.parent, with_prefixes, multi_instance)
        return p + "/" + name(s) + suffix

def get_xpath(s, with_prefixes=True):
    if s.keyword in ['choice', 'case']:
        return get_xpath(s.parent)
    def name(s):
        if with_prefixes:
            return s.i_module.i_prefix + ":" + s.arg
        else:
            return s.arg
    if s.parent.keyword in ['module', 'submodule', 'grouping']:
        return "/" + name(s)
    else:
        p = get_xpath(s.parent, with_prefixes)
        return p + "/" + name(s)

#seek and return the actual builtin type
def seek_type(type, child, builtin_types, typedefs):
    if type.arg not in builtin_types:
        module_prefix = ''
        if ':' not in type.arg:
            module_prefix = child.i_module.i_prefix + ':'
        type = typedefs[module_prefix + type.arg].search_one('type')
        return seek_type(type, child, builtin_types, typedefs)
    else:
        return type

def make_chain(chain_list):
    if chain_list == []:
        return [0, 'NULL']

    chain_cnt = len(chain_list)
    chain = '{ '
    for elem in chain_list:
        chain += "DM_" + elem.upper() + ", "
    chain += "}"
    return [chain_cnt, chain]

def make_action(action_string, action):
    if action_string != 'NULL':
        return "dm_" + action.arg + "_action"
    else:
        return 'NULL'

def make_license(fd):
    fd.write("""/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *
 * WARNING: This file has been autogenerated by yang/pyang_plugin/OpenCPE.py
 *
 *            !!! DO NOT MODIFY MANUALLY !!!
*/
\n""")

def generate_action_table(actions, fd):
    make_license(fd)
    fd.write("""
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dm_token.h"
#include "dm_action.h"
#include "dm_action_table.h"

""")

    # first complete the header with the include statements
    for action in actions:
        include = action.search_one(('opencpe-actiontable', 'include')).arg
        if include != 'NULL':
            fd.write( "#include \"" + include + "\"\n")
    fd.write("\n")

    chains = {}
    for action in actions:
        chain_string = action.search_one(('opencpe-actiontable', 'chain')).arg
        chains[action.arg] = chain_string
    [chains, actions_order] = make_chains( chains )

    # order the actions according to the new order (given by the path lengths)
    actions = order_actions(actions, actions_order)

    for action in actions:
        fd.write("/* " + action.search_one(('opencpe-actiontable', 'comment')).arg + " */\n")
        fd.write("static struct dm_action dm_" + action.arg +  " = {\n")
        fd.write(tab + ".sel_len = " + action.search_one(('opencpe-actiontable', 'sel')).arg + ",\n\n")
        fd.write(tab + ".pre = " + action.search_one(('opencpe-actiontable', 'pre')).arg + ",\n")

        action_string = action.search_one(('opencpe-actiontable', 'action')).arg
        action_string = make_action(action_string, action)
        fd.write(tab + ".action = " + action_string + ",\n")

        fd.write(tab + ".post = " + action.search_one(('opencpe-actiontable', 'post')).arg + ",\n\n")

        [chain_cnt, chain] = make_chain( chains[action.arg] )
        fd.write(tab + ".chain_cnt = " + str(chain_cnt) + ",\n")
        if chain != 'NULL':
            fd.write(tab + ".chain = " + chain + ",\n")
        fd.write("};\n\n")

    fd.write("const struct dm_action *dm_actions[] = {\n")
    for action in actions:
        fd.write(tab + "[DM_" + action.arg.upper() + "] = &dm_" + action.arg + ",\n")
    fd.write("};\n")

def generate_action_table_header(actions, fd):
    make_license(fd)
    fd.write("""
#ifndef __DM_ACTION_TABLE_H
#define __DM_ACTION_TABLE_H

enum dm_actions {\n""")
    fd.write( tab + "DM_NONE,\n")

    for action in actions:
        fd.write( tab + "DM_" + action.arg.upper() + ",\n")
    fd.write("};\n\n")
    fd.write("#endif\n")

def generate_debug_table(actions, fd):
    make_license(fd)
    fd.write("static const char *t_actions[] = {\n")

    fd.write( tab + "type_map_init(DM_NONE),\n")
    for action in actions:
        fd.write( tab + "type_map_init(DM_" + action.arg.upper() + "),\n")
    fd.write("};\n\n")


#########
#The following code will implement an algortithm for the transitive reduction of a graph.
#This is needed to handle actions which occour more than once in a chain. The action chains will
#be cut at points where another chain would already consider the elements afterwards.
#########

#the actual transitive reduction: M^- = M - ( M \circ M^+ ) where M^- is the transitive reduction and M^+ is the transitive closure.
def trans_reduct(M):
    trans_closure = warshall(M)
    composition = rel_mult(M, trans_closure)
    trans_reduct = set_substr(M, composition)
    return trans_reduct

#defines a substraction on matrices, negative entries are normalized to 0
def set_substr(M1, M2):
    n = len(M1)
    new_matrix = zero(n)
    for i in range(n):
        for j in range(n):
            new_matrix[i][j] = M1[i][j] - M2[i][j]
            if new_matrix[i][j] < 0:
                new_matrix[i][j] = 0
    return new_matrix

#defines a multiplication on matrices, entries >0 are normalized to 1
def rel_mult(M1, M2):
    n = len(M1)
    new_matrix = zero(n)
    for i in range(n):
        for j in range(n):
            for k in range(n):
                new_matrix[i][j] += M1[i][k] * M2[k][j]
            if new_matrix[i][j] > 0:
                new_matrix[i][j] = 1
    return new_matrix

#the warshall algorithm, computes the transitive closure of a graph
def warshall(M):
    Mw = deepcopy(M)
    n = len(Mw)
    for k in range(n):
        for i in range(n):
            if Mw[i][k] == 1:
                for j in range(n):
                    if Mw[k][j] == 1:
                        Mw[i][j] = 1
    return Mw

# Create zero matrix
def zero(n):
    new_matrix = [[0 for row in range(n)] for col in range(n)]
    return new_matrix

# the code regarding the transitive reduction is now used here
def make_chains(chains):
    keys = chains.keys()
    n = len(keys)

    for action in keys:
        if chains[action] == 'NULL':
            chains[action] = []
        else:
            chains[action] = chains[action].split(';')

    # create an adjacency matrix from the chains
    adj_matrix = zero(n)
    for action in keys:
        for chain_action in chains[action]:
            adj_matrix[keys.index(action)][keys.index(chain_action)] = 1

    # do the transitive reduction on the adjacency matrix.
    adj_matrix = trans_reduct(adj_matrix)

    # and now adjust the old chains with the updated adjacency matrix
    for i in range(n):
        for j in range(n):
            if adj_matrix[i][j] == 0 and keys[j] in chains[keys[i]]:
                chains[keys[i]].remove(keys[j])

    # The action fields need to be reordered according to their depth in the graph.
    # Nodes with greater depth occour at least -> depth first search

    # here comes the depth first search, the depths of the action nodes
    # are stored in depths and updated with every recursion
    def depth_first(keys_index, depth):
        if depth > depths[keys_index]:
            depths[keys_index] = depth
        chain_nodes = chains[keys[keys_index]]
        if chain_nodes == []:
            return
        else:
            for chain_node in chain_nodes:
                index = keys.index(chain_node)
                depth_first(index, depth+1)

    # now do the depth first search
    depths = [0] * n
    for key in keys:
        depth_first(keys.index(key), 0)

    # now the actions only need to be reordered according to the depths
    # first get all unique depths (will be sorted automatically):
    unique_depths = list(set(depths))
    actions_order = []
    for unique_depth in unique_depths:
        for i in range(n):
            if depths[i] == unique_depth:
                actions_order.append(keys[i])

    return [chains, actions_order]


def order_actions(actions, actions_order):
    ordered_actions = []
    for action_arg in actions_order:
        for action in actions:
            if action.arg == action_arg:
                ordered_actions.append(action)
    return ordered_actions

