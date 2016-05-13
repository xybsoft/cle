# add support to load mc7 code, edited by xybsoft

import archinfo
from archinfo import ArchS7XX
import os
import struct
import datetime
from ..backends import Backend, Symbol, Region
from ..relocations import Relocation
from ..errors import CLEError, CLEInvalidBinaryError, CLECompatibilityError

__all__ = ('MC7', )

PlcLanguages = {1:'AWL', 2:'LAD', 3:'FUP', 4:'SCL', 5:'DB', 6:'GRAPH'}

PlcBlockType = {    \
    0x08:'OB', \
    0x0A:'DB', \
    0x0B:'SDB', \
    0x0C:'FC', \
    0x0D:'SFC', \
    0x0E:'FB', \
    0x0F:'SFB' }

MC7RowType = { \
    0x1 : 'IN', \
    0x9 : 'IN', \
    0x2 : 'OUT', \
    0xA : 'OUT', \
    0x3 : 'IN_OUT', \
    0xB : 'IN_OUT', \
    0x4 : 'STAT', \
    0xC : 'STAT', \
    0x5 : 'TEMP', \
    0x6 : 'RET_VAL' }

MC7ParamType = { \
    0x1 : 'BOOL', \
    0x2 : 'BYTE', \
    0x3 : 'CHAR', \
    0x4 : 'WORD', \
    0x5 : 'INT', \
    0x6 : 'DWORD', \
    0x7 : 'DINT', \
    0x8 : 'REAL', \
    0x9 : 'DATE', \
    0xA : 'TIME_OF_DAY', \
    0xB : 'TIME', \
    0xC : 'S5TIME', \
    0xE : 'DATE_AND_TIME', \
    0x10 : 'ARRAY', \
    0x11 : 'STRUCT', \
    0x13 : 'STRING', \
    0x14 : 'POINTER', \
    0x16 : 'ANY', \
    0x17 : 'BLOCK_FB', \
    0x18 : 'BLOCK_FC', \
    0x19 : 'BLOCK_DB', \
    0x1A : 'BLOCK_SDB', \
    0x1C : 'COUNTER', \
    0x1D : 'TIMER' }

MC7HeaderLength = 36

def get_byte(s, i):
    """
    get a byte from a string
    
    s is a string, i is the offset
    """
    
    return struct.unpack('B', s[i])[0]

def get_short(s, i, endian='LE'):
    """
    get a short (16 bits) from a string
    
    s is a string, i is the offset
    endian: 'LE', little endian
            'BE', bit endian
    """
    
    if endian == 'LE':
        return struct.unpack('<H', s[i:i+2])[0]
    else:
        return struct.unpack('>H', s[i:i+2])[0]
    
def get_int(s, i, endian='LE'):
    """
    get a short (16 bits) from a string
    
    s is a string, i is the offset
    endian: 'LE', little endian
            'BE', bit endian
    """
    
    if endian == 'LE':
        return struct.unpack('<I', s[i:i+4])[0]
    else:
        return struct.unpack('>I', s[i:i+4])[0]
    
def get_datetime(s):
    """
    convert a mc7 datetime binary representation to a datetime data
    
    s: a representation of mc7 datatime, 6 bytes length
    """
    
    dt_start = datetime.datetime(1984, 1, 1)
    # ms: a 32bit data, represents the milliseconds passed
    ms = get_int(s, 0, 'BE')
    # d: a 16bit data, represents the day passed
    d = get_short(s, 4, 'BE')
    td = datetime.timedelta(days=d, microseconds=ms)
    dt = dt_start + td
    return dt
    
class MC7Parameter(object):
    def __init__(self, name, row_type, param_type):
        self.name = name
        self.row_type = row_type
        self.param_type = param_type

class MC7Network(Region):
    def __init__(self, name, offset, addr, size):
        super(MC7Network, self).__init__(offset, addr, size, size)
        self.name = name
    
class MC7(Backend):
    """
    Represents a Siemens MC7 binary
    :ivar binary:           The path to the file this object is loaded from
    :ivar is_main_bin:      Whether this binary is loaded as the main executable
    :ivar segments:         A listing of all the loaded segments in this file
    :ivar sections:         A listing of all the demarked sections in the file
    :ivar sections_map:     A dict mapping from section name to section
    :ivar symbols_by_addr:  A mapping from address to Symbol
    :ivar imports:          A mapping from symbol name to import symbol
    :ivar resolved_imports: A list of all the import symbols that are successfully resolved
    :ivar relocs:           A list of all the relocations in this binary
    :ivar irelatives:       A list of tuples representing all the irelative relocations that need to be performed. The
                            first item in the tuple is the address of the resolver function, and the second item is the
                            address of where to write the result. The destination address is not rebased.
    :ivar jmprel:           A mapping from symbol name to the address of its jump slot relocation, i.e. its GOT entry.
    :ivar arch:             The architecture of this binary
    :vartype arch:          archinfo.arch.Arch
    :ivar str filetype:     The filetype of this object
    :ivar str os:           The operating system this binary is meant to run under
    :ivar compatible_with:  Another Backend object this object must be compatibile with, or None
    :ivar int rebase_addr:  The base address of this object in virtual memory
    :ivar tls_module_id:    The thread-local storage module ID assigned to this binary
    :ivar deps:             A list of names of shared libraries this binary depends on
    :ivar linking:          'dynamic' or 'static'
    :ivar requested_base:   The base address this object requests to be loaded at, or None
    :ivar bool pic:         Whether this object is position-independant
    :ivar bool execstack:   Whether this executable has an executable stack
    :ivar str provides:     The name of the shared library dependancy that this object resolves
    """    
    
    def __init__(self, binary, **kwargs):
        super(MC7, self).__init__(binary, **kwargs)
        
        if self.arch == None:
            self.set_arch(ArchS7XX())
        # default entry is 0
        self._entry = 0
        
        # the header of mc7 contains 36 bytes
        self._header_length = MC7HeaderLength
        self.binary_stream.seek(0, 0)
        header = self.binary_stream.read(self._header_length)
        
        self._version = str(get_byte(header, 2) - 1)
        self._attribute = str(get_byte(header, 3) - 1)
        language = get_byte(header, 4)
        self._language = PlcLanguages[language] if language in PlcLanguages else 'Unknown'
        block_type = get_byte(header, 5)
        self._block_type = PlcBlockType[block_type] if block_type in PlcBlockType else 'Unknown'
        # DB and SDB are not executable
        if self._block_type in ('DB', 'SDB', 'Unknown'):
            raise CLECompatibilityError('The binary is not executable')
        self._block_number = get_short(header, 6, 'BE')
        self._block_length = get_int(header, 8, 'BE')
        self._password = get_int(header, 12, 'BE')
        self._dt_block_modified = get_datetime(header[16:22])
        self._dt_interface_modified = get_datetime(header[22:28])
        self._interface_length = get_short(header, 28, 'BE')
        self._segment_length = get_short(header, 30, 'BE')
        self._data_length = get_short(header, 32, 'BE')
        self._mc7_length = get_short(header, 34, 'BE')
        
        self._if_start = self._header_length + self._mc7_length
        self.binary_stream.seek(self._if_start, 0)
        if_header = self.binary_stream.read(5)
        if if_header[0] != '\x01':
            raise CLEInvalidBinaryError('Can not find interface header')  
        para_length = get_short(if_header, 3, 'LE');
        if para_length + 8 != self._interface_length:
            # the header 3 bytes, length 2 bytes, tail 3 bytes, 8 bytes total
            raise CLEInvalidBinaryError('Parse interface data error')
        
        self._networks_start = self._if_start + self._interface_length
        
        self.binary_stream.seek(self._header_length, 0)
        self.memory.add_backer(0, self.binary_stream.read(self._mc7_length))
        # TODO: add FC, SFC, FB, SFB as deps
        
    def get_min_addr(self):
        return 0
    
    def get_max_addr(self):
        return self._mc7_length
    
    def get_parameters(self):
        self.binary_stream.seek(self._if_start, 0)
        parameters = []
        buf = self.binary_stream.read(self._interface_length)

        counter = 0
        pos = 7
        while pos <= self._interface_length - 3:
            row_type = get_byte(buf, pos+1)
            param_type = get_byte(buf, pos)
            row_type_name = MC7RowType[row_type] if row_type in MC7RowType else 'Unknown'
            # the block is not a data block, so do not need to check startval
            if param_type == 0x10:
                # TODO: Array data type
                pass
            elif param_type == 0x11:
                # TODO: struct data type
                pass
            elif param_type == 0x13:
                # TODO: string data type
                pass
            else:
                para = MC7Parameter(row_type_name + str(counter), row_type, param_type)
                parameters.append(para)
                pos += 2
                counter += 1
        return parameters
    
    def get_networks(self):
        self.binary_stream.seek(self._networks_start, 0)
        buf = self.binary_stream.read(self._segment_length)
        networks_length = get_short(buf, 0, 'LE')
        networks_size = networks_length / 2
        counter = 0
        pos = 2
        networks = []
        addr = 0
        for i in range(1, networks_size+1):
            size = get_short(buf, pos, 'LE')
            offset = self._header_length + addr
            nw = MC7Network('Network' + str(i), offset, addr, size)
            addr = size
        pass
    
        
        
    supported_filetypes = ['mc7']