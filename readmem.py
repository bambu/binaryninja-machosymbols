import struct

ASCSTR_C = None
bv = None


def initialize_idc(view):
    global bv
    bv = view


def get_num_by_size(start, size, is_be, view=None):
    view = view or bv
    if view is None:
        raise ValueError('view')

    fmt = '>' if is_be else '<'
    if size == 4:
        fmt += 'I'
    elif size == 8:
        fmt += 'Q'
    elif size == 2:
        fmt += 'H'
    elif size == 1:
        fmt += 'B'
    else:
        raise ValueError('Valid values B, H, I Q')

    raw = struct.unpack_from(fmt, view.read(start, size))

    return raw[0] if raw else -1


def Pointer(start, is_be=False, view=None):
    view = view or bv
    if view is None:
        raise ValueError('view')

    size = view.arch.address_size
    return get_num_by_size(start, size, is_be, view)


def Qword(start, is_be=False, view=None):
    """ Return a qword at the specified location """
    return get_num_by_size(start, 8, is_be, view)


def Dword(start, is_be=False, view=None):
    """ Return a dword at the specified location """
    return get_num_by_size(start, 4, is_be, view)


def Word(start, is_be=False, view=None):
    """ Return a word at the specified location """
    return get_num_by_size(start, 2, is_be, view)


def Byte(start, view=None):
    """ Return a byte at the specified location """
    view = view or bv
    if view is None:
        raise ValueError('view')

    return ord(view.read(start, 1))


def GetString(start, length=-1, strtype=ASCSTR_C, view=None, max_read=200):
    """ Return a string at the specified location """
    view = view or bv
    if view is None:
        raise ValueError('view')

    if length == -1:
        str_refs = view.get_strings(start, 1)
        if str_refs:
            str_ref = str_refs[0]
            length = str_ref.length
        else:
            print('Here with %#x' % start)
            data = view.read(start, max_read)
            end = data.find('\x00')
            if end == -1:
                return

            return data[:end]

    return view.read(start, length)
