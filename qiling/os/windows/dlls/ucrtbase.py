#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling.os.windows.dlls.msvcrt import *

@winsdkapi(cc=CDECL, params={'table' : ctypes.c_uint64})
def hook__initialize_onexit_table(ql: Qiling, address: int, params: dict): 
    table = params["table"]  
    
    if table is None:
        return -1

    module_name = 'ucrtbase.dll'
    rva = 0xEF450

    for base, _, path in ql.loader.images:
        if os.path.basename(path).casefold() == module_name:
            absolute_address = base + rva
            
            memory_bytes = ql.mem.read(absolute_address, 0x8)
            memory_bytes = bytes(memory_bytes)

            ql.mem.write(table, memory_bytes)
            ql.mem.write(table + 8, memory_bytes)
            ql.mem.write(table + 16, memory_bytes)

            return 0