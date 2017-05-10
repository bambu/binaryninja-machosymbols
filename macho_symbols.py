from __future__ import absolute_import

import struct
import sys
import subprocess

from tempfile import NamedTemporaryFile

from binaryninja import Symbol, SymbolType

from .readmem import initialize_idc, Pointer, GetString


def make_name_from_str(string, max_size=100):
    """ Return a name that is capitalized and without spaces """
    return ''.join(
        '%s%s' % (w[0].upper(), w[1:])
        for w in string.split()
    )[:max_size]


def generate_selrefs(view):
    """ Create symbols for entries in __objc_selrefs section """
    if view.view_type != 'Mach-O':
        return

    selrefs = view.sections.get('__objc_selrefs', None)
    if not selrefs:
        return

    initialize_idc(view)

    size = view.arch.address_size
    view.begin_undo_actions()
    for address in xrange(selrefs.start, selrefs.end, size):
        if view.get_symbol_at(address):
            continue

        ref_str = GetString(Pointer(address))
        symbol_name = 'selRef_' + make_name_from_str(ref_str)
        view.define_user_symbol(Symbol(
            SymbolType.DataSymbol,
            address,
            symbol_name
        ))

    view.commit_undo_actions()


def generate_bind_symbols(view):
    """ Generate bind symbols using dyldinfo command """
    if view.view_type != 'Mach-O':
        return

    if sys.platform != 'darwin':
        return

    raw_view = view.get_view_of_type('Raw')
    with NamedTemporaryFile() as data_file:
        data_file.write(raw_view.read(0, len(raw_view)))
        data_file.flush()
        output = subprocess.check_output(
            'xcrun dyldinfo -bind %s | tail -n +3' % data_file.name,
            shell=True
        )

    view.begin_undo_actions()
    for line in output.splitlines():
        _, section, address, _, _, _, symbol = line.split()[:7]
        address = int(address, 0)
        if view.get_symbol_at(address):
            continue

        if section == '__got':
            symbol_type = SymbolType.ImportedFunctionSymbol
        else:
            symbol_type = SymbolType.DataSymbol

        # print address, dylib, symbol
        view.define_user_symbol(Symbol(symbol_type, address, symbol))

    view.commit_undo_actions()


class Objc2Class(object):
    """
    struct __objc2_class
    {
        __objc2_class *isa;
        __objc2_class *superclass;
        void *cache;
        void *vtable;
        __objc2_class_ro *info;
    };
    """
    fmt = '<QQQQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.isa,
         self.superclass,
         self.cache,
         self.vtable,
         self.info) = struct.unpack_from(self.fmt, data, offset)


class Objc2ClassRo(object):
    """
    struct __objc2_class_ro
    {
        uint32_t flags;
        uint32_t ivar_base_start;
        uint32_t ivar_base_size;
        uint32_t reserved;
        void *ivar_lyt;
        char *name;
        __objc2_meth_list *base_meths;
        __objc2_prot_list *base_prots;
        __objc2_ivar_list *ivars;
        void *weak_ivar_lyt;
        __objc2_prop_list *base_props;
    };
    """
    fmt = '<IIIIQQQQQQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.flags,
         self.ivar_base_start,
         self.ivar_base_size,
         self.reserved,
         self.ivar_lyt,
         self.name,
         self.base_meths,
         self.base_prots,
         self.ivars,
         self.weak_ivar_lyt,
         self.base_props) = struct.unpack_from(self.fmt, data, offset)


def generate_function_names(view):
    """ Generate symbols for Objective-C functions """
    if view.view_type != 'Mach-O':
        return

    # Only 64bit supported currently
    ptr_size = view.arch.address_size
    if ptr_size != 8:
        return

    try:
        class_list = view.sections['__objc_classlist']
        data_section = view.sections['__objc_data']
        const_section = view.sections['__objc_const']
    except KeyError:
        return

    classlist_pointers = struct.unpack(
        '<' + 'Q' * (len(class_list)/ptr_size),
        view.read(class_list.start, len(class_list))
    )

    data_content = view.read(data_section.start, data_section.length)
    const_content = view.read(const_section.start, const_section.length)

    initialize_idc(view)
    view.begin_undo_actions()

    for class_pointer in classlist_pointers:
        objc_class = Objc2Class(data_content, class_pointer - data_section.start)

        objc_meta = Objc2Class(data_content, objc_class.isa - data_section.start)

        metadata = Objc2ClassRo(const_content, objc_meta.info - const_section.start)
        classdata = Objc2ClassRo(const_content, objc_class.info - const_section.start)

        class_name = GetString(metadata.name)

        for selector_name, imp in get_methods(classdata, const_content, const_section.start):
            function = view.get_function_at(imp)
            function.name = '-[%s %s]' % (class_name, selector_name)

        for selector_name, imp in get_methods(metadata, const_content, const_section.start):
            function = view.get_function_at(imp)
            function.name = '+[%s %s]' % (class_name, selector_name)

    view.commit_undo_actions()
    view.update_analysis()


def get_methods(class_ro, content, section_base):
    """ Retrieve objc2_meth from read only class """
    if class_ro.base_meths == 0:
        raise StopIteration

    # skip to first method
    offset = class_ro.base_meths + 8 - section_base
    num_methods = struct.unpack_from('<I', content, offset - 4)[0]
    for offset in xrange(offset, offset + num_methods * 0x18, 0x18):
        name, _, imp = struct.unpack_from('<QQQ', content, offset)
        yield GetString(name), imp
