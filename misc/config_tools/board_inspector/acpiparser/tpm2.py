# Copyright (C) 2021 Intel Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import ctypes
import logging

import lib.cdata as cdata
from acpiparser._utils import TableHeader

def StartMethodSpecificParameters_factory():
    class StartMethodSpecificParameters(cdata.Struct):
        _pack_ = 1
        _fields_ = [
            ('interrupt', ctypes.c_uint32),
            ('flags', ctypes.c_ubyte),
            ('operation_flags', ctypes.c_ubyte),
            ('reserved', ctypes.c_uint16),
            ('SMC_function_id', ctypes.c_uint32),
        ]
    return StartMethodSpecificParameters

class TPM2Metadata:
    def __init__(self, **kwargs):
        self.metadata = {}
        for key, value in kwargs.items():
            if key == "oemid":
                if not isinstance(value, str):
                    raise TypeError(f"oemid must be a string: {type(value)}")
                if len(value) > 6:
                    raise IndexError(f"oemid must be fitted in 6 bytes: length of oemid {len(value)}")
                self.metadata[key] = value.encode()
            elif key == "oemtableid":
                if not isinstance(value, str):
                    raise TypeError(f"oemtableid must be a string: {type(value)}")
                if len(value) > 8:
                    raise IndexError(f"oemtableid must be fitted in 8 bytes: length of oemtableid {len(value)}")
                self.metadata[key] = value.encode()
            elif key == "creatorid":
                if not isinstance(value, str):
                    raise TypeError(f"creatorid must be a string: {type(value)}")
                if len(value) > 4:
                    raise IndexError(f"creatorid must be fitted in 4 bytes: length of creatorid {len(value)}")
                self.metadata[key] = value.encode()
            elif key == "creatorrevision":
                if not isinstance(value, int):
                    raise TypeError(f"creatorrevision must be an integer: {type(value)}")
                if value < 0 or value > 0xFFFFFFFF:
                    raise ValueError(f"creatorrevision must be in range[0:0xFFFFFFFF]: {hex(value)}")
                self.metadata[key] = value.to_bytes(4, 'little')
            elif key == "controlarea":
                if not isinstance(value, int):
                    raise TypeError(f"controlarea must be an integer: {type(value)}")
                if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
                    raise ValueError(f"controlarea must be in range[0:0xFFFFFFFFFFFFFFFF]: {hex(value)}")
                self.metadata[key] = value.to_bytes(8, 'little')
            else:
                logging.warning("unknown field:value = {key}:{value} is specified, this data is discard.")
        checksum = 0
        self.metadata["checksum"] = checksum.to_bytes(1, 'little')

    def create(self, data):
        data_len = len(data)
        _data = bytearray()
        _data += data[0:9]
        _data += self.metadata["checksum"] if "checksum" in self.metadata else data[9]
        _data += self.metadata["oemid"] if "oemid" in self.metadata else data[10:16]
        _data += self.metadata["oemtableid"] if "oemtableid" in self.metadata else data[16:24]
        _data += data[24:28]
        _data += self.metadata["creatorid"] if "creatorid" in self.metadata else data[28:32]
        _data += self.metadata["creatorrevision"] if "creatorrevision" in self.metadata else data[32:36]
        _data += data[36:40]
        _data += self.metadata["controlarea"] if "controlarea" in self.metadata else data[40:48]
        _data += data[48:52]
        _data += bytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])
        log_area_minimum_length = 0x10000
        _data += log_area_minimum_length.to_bytes(4, 'little')
        log_area_minimum_length = 0x44a59000
        _data += log_area_minimum_length.to_bytes(8, 'little')

        new_checksum = (~(sum(_data)) + 1) & 0xFF
        with open("tpm2", 'wb') as file:
            file.write(_data[0:9] + new_checksum.to_bytes(1, 'little') + _data[10:])
        file.close()

def tpm2_optional_data(data_len):
    start_method_data_len = 0
    has_log_area = False
    if data_len <= 12:
        start_method_data_len = data_len
    elif data_len == 24:
        start_method_data_len = 12
        has_log_area = True
    else:
        start_method_data_len = 12
        logging.warning(f"TPM2 data length: {data_len + 52} is greater than 64 bytes but less than 76 bytes.")
        logging.warning(f"The TPM2 data is still processed but the 65 to {data_len + 52} bytes is discard.")
    return start_method_data_len, has_log_area

def tpm2_factory(start_method_data_len, has_log_area):
    class TPM2(cdata.Struct):
        _pack_ = 1
        _fields_ = [
            ('header', TableHeader),
            ('platform_class', ctypes.c_uint16),
            ('reserved', ctypes.c_uint16),
            ('address_of_control_area', ctypes.c_uint64),
            ('start_method', ctypes.c_uint32),
            ('start_method_specific_parameters', ctypes.c_ubyte * start_method_data_len),
        ] + ([
            ('log_area_minimum_length', ctypes.c_uint32),
            ('log_area_start_address', ctypes.c_uint64),
        ] if has_log_area else [])

    return TPM2

def TPM2(val):
    """Create class based on decode of a TPM2 table from filename."""
    if isinstance(val, str):
        base_length = 52
        data = open(val, mode='rb').read()
        start_method_data_len, has_log_area = tpm2_optional_data(len(data) - base_length)
        return tpm2_factory(start_method_data_len, has_log_area).from_buffer_copy(data)
    elif isinstance(val, bytearray):
        return tpm2_factory(12, True).from_buffer_copy(val) if len(val) > 64 else tpm2_factory(12, False).from_buffer_copy(val)
