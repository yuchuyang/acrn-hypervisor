# Copyright (C) 2019 Intel Corporation.
# SPDX-License-Identifier: BSD-3-Clause

"""the tool to generate ACPI binary for Pre-launched VMs.

"""

import ctypes
import logging
import os, sys, subprocess, argparse, re, shutil
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'board_inspector'))
import lxml.etree
from acpi_const import *
from acpiparser import tpm2
import lib.cdata
import common

def HeaderData(**kwargs):
    data = {}
    for key, value in kwargs.items():
        if key == "signature":
            if not isinstance(value, str):
                raise TypeError(f"signature must be a string: {type(value)}")
            if len(value) > 4:
                raise IndexError(f"signature must be fitted in 4 bytes: length of signature {len(value)}")
            data[key] = value.encode()
        elif key == "length":
            if not isinstance(value, int):
                raise TypeError(f"length must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFFFFFF:
                raise ValueError(f"length must be in range[0:0xFFFFFFFF]: {hex(value)}")
            data[key] = value.to_bytes(4, 'little')
        elif key == "revision":
            if not isinstance(value, int):
                raise TypeError(f"revision must be an integer: {type(value)}")
            if value < 0 or value > 0xFF:
                raise ValueError(f"revision must be in range[0:0xFF]: {hex(value)}")
            data[key] = value.to_bytes(1, 'little')
        elif key == "oemid":
            if not isinstance(value, str):
                raise TypeError(f"oemid must be a string: {type(value)}")
            if len(value) > 6:
                raise IndexError(f"oemid must be fitted in 6 bytes: length of oemid {len(value)}")
            data[key] = value.encode()
        elif key == "oemtableid":
            if not isinstance(value, str):
                raise TypeError(f"oemtableid must be a string: {type(value)}")
            if len(value) > 8:
                raise IndexError(f"oemtableid must be fitted in 8 bytes: length of oemtableid {len(value)}")
            data[key] = value.encode()
        elif key == "oemrevision":
            if not isinstance(value, int):
                raise TypeError(f"oemrevision must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFFFFFF:
                raise ValueError(f"oemrevision must be in range[0:0xFFFFFFFF]: {hex(value)}")
            data[key] = value.to_bytes(4, 'little')
        elif key == "creatorid":
            if not isinstance(value, str):
                raise TypeError(f"creatorid must be a string: {type(value)}")
            if len(value) > 4:
                raise IndexError(f"creatorid must be fitted in 4 bytes: length of creatorid {len(value)}")
            data[key] = value.encode()
        elif key == "creatorrevision":
            if not isinstance(value, int):
                raise TypeError(f"creatorrevision must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFFFFFF:
                raise ValueError(f"creatorrevision must be in range[0:0xFFFFFFFF]: {hex(value)}")
            data[key] = value.to_bytes(4, 'little')
        elif key == "platformclass":
            if not isinstance(value, int):
                raise TypeError(f"platformclass must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFF:
                raise ValueError(f"platformclass must be in range[0:0xFFFF]: {hex(value)}")
            data[key] = value.to_bytes(2, 'little')
        else:
            logging.warning("unknown field:value = {key}:{value} is specified, this data is discard.")
    return data

def TPM2Metadata(tpm2_node):
    data = HeaderData(
        signature = "TPM2",
        length = int(common.get_node("./table_length/text()", tpm2_node), 16),
        revision = 0x3,
        oemid = "ACRN  ",
        oemtableid = "ACRNTPM2",
        oemrevision = 0x1,
        creatorid = "INTL",
        creatorrevision = 0x20190703,
        platformclass = 0x0,
        )
    data["reserved"] = int("0", 16).to_bytes(2, 'little')
    data["controlarea"] = int("FED40040", 16).to_bytes(8, 'little')
    data["start_method"] = int(common.get_node("./capability[@id = 'start_method']/value/text()", tpm2_node), 16).to_bytes(4, 'little')
    start_method_specific_parameters = [int(parameter, 16) for parameter in tpm2_node.xpath("//parameters")]
    if len(start_method_specific_parameters) > 0:
        data["start_method_specific_parameters"] = bytes(start_method_specific_parameters)
    log_area_minimum_length = common.get_node("//log_area_minimum_length", tpm2_node)
    if log_area_minimum_length is not None:
        data["log_area_minimum_length"] = int(log_area_minimum_length, 16).to_bytes(4, 'little')
    log_area_start_address = common.get_node("//log_area_start_address", tpm2_node)
    if log_area_start_address is not None:
        data["log_area_start_address"] = int(log_area_start_address, 16).to_bytes(8, 'little')
    return data
    """
    for key, value in kwargs.items():
        if key == "controlarea":
            if not isinstance(value, int):
                raise TypeError(f"controlarea must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"controlarea must be in range[0:0xFFFFFFFFFFFFFFFF]: {hex(value)}")
            self.metadata[key] = value.to_bytes(8, 'big')
        elif key == "start_method":
            if not isinstance(value, int):
                raise TypeError(f"start_method must be an integer: {type(value)}")
            if value < 0 or value > 11:
                raise ValueError(f"start_method must be in range[0:0xB]: {hex(value)}")
            self.metadata[key] = bytes(value)
        elif key == "start_method_specific_parameters":
            if not isinstance(value, list):
                raise TypeError(f"start_method_specific_parameters must be a list: {type(value)}")
            self.metadata[key] = bytes(value)
        elif key == "log_area_minimum_length":
            if not isinstance(value, int):
                raise TypeError(f"log_area_minimum_length must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFFFFFF:
                raise ValueError(f"log_area_minimum_length must be in range[0:0xFFFFFFFF]: {hex(value)}")
            self.metadata[key] = value.to_bytes(4, 'big')
        elif key == "log_area_start_address":
            if not isinstance(value, int):
                raise TypeError(f"log_area_start_address must be an integer: {type(value)}")
            if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"log_area_start_address must be in range[0:0xFFFFFFFFFFFFFFFF]: {hex(value)}")
            self.metadata[key] = value.to_bytes(8, 'big')
        else:
            logging.warning("unknown field:value = {key}:{value} is specified, this data is discard.")
        """

def asl_to_aml(dest_vm_acpi_path, dest_vm_acpi_bin_path):
    '''
    compile asl code of ACPI table to aml code.
    :param dest_vm_acpi_path: the path of the asl code of ACPI tables
    :param dest_vm_acpi_bin_path: the path of the aml code of ACPI tables
    :param passthru_devices: passthrough devce list
    :return:
    '''
    curr_path = os.getcwd()
    rmsg = ''

    os.chdir(dest_vm_acpi_path)
    for acpi_table in ACPI_TABLE_LIST:
        if acpi_table[0] == 'tpm2.asl':
            if 'tpm2.asl' in os.listdir(dest_vm_acpi_path):
                rc = exec_command('iasl {}'.format(acpi_table[0]))
                if rc == 0 and os.path.isfile(os.path.join(dest_vm_acpi_path, acpi_table[1])):
                    shutil.move(os.path.join(dest_vm_acpi_path, acpi_table[1]),
                                os.path.join(dest_vm_acpi_bin_path, acpi_table[1]))
                else:
                    if os.path.isfile(os.path.join(dest_vm_acpi_path, acpi_table[1])):
                        os.remove(os.path.join(dest_vm_acpi_path, acpi_table[1]))
                    rmsg = 'failed to compile {}'.format(acpi_table[0])
                    break
        elif acpi_table[0] == 'PTCT':
            if 'PTCT' in os.listdir(dest_vm_acpi_path):
                shutil.copyfile(os.path.join(dest_vm_acpi_path, acpi_table[0]),
                                os.path.join(dest_vm_acpi_bin_path, acpi_table[1]))
        elif acpi_table[0] == 'RTCT':
            if 'RTCT' in os.listdir(dest_vm_acpi_path):
                shutil.copyfile(os.path.join(dest_vm_acpi_path, acpi_table[0]),
                                os.path.join(dest_vm_acpi_bin_path, acpi_table[1]))
        else:
            rc = exec_command('iasl {}'.format(acpi_table[0]))
            if rc == 0 and os.path.isfile(os.path.join(dest_vm_acpi_path, acpi_table[1])):
                shutil.move(os.path.join(dest_vm_acpi_path, acpi_table[1]),
                            os.path.join(dest_vm_acpi_bin_path, acpi_table[1]))
            else:
                if os.path.isfile(os.path.join(dest_vm_acpi_path, acpi_table[1])):
                    os.remove(os.path.join(dest_vm_acpi_path, acpi_table[1]))
                rmsg = 'failed to compile {}'.format(acpi_table[0])
                break

    os.chdir(curr_path)
    if not rmsg:
        print('compile ACPI ASL code to {} successfully'.format(dest_vm_acpi_bin_path))
    return rmsg



def aml_to_bin(dest_vm_acpi_path, dest_vm_acpi_bin_path, acpi_bin_name, board_etree, scenario_etree):
    '''
    create the binary of ACPI table.
    :param dest_vm_acpi_bin_path: the path of the aml code of ACPI tables
    :param acpi_bin: the binary file name of ACPI tables
    :param passthru_devices: passthrough devce list
    :return:
    '''
    acpi_bin_file = os.path.join(dest_vm_acpi_bin_path, acpi_bin_name)
    if os.path.isfile(acpi_bin_file):
        os.remove(acpi_bin_file)
    with open(acpi_bin_file, 'wb') as acpi_bin:
        # acpi_bin.seek(ACPI_RSDP_ADDR_OFFSET)
        # with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[0][1]), 'rb') as asl:
        #     acpi_bin.write(asl.read())

        acpi_bin.seek(ACPI_XSDT_ADDR_OFFSET)
        with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[1][1]), 'rb') as asl:
            acpi_bin.write(asl.read())

        acpi_bin.seek(ACPI_FADT_ADDR_OFFSET)
        with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[2][1]), 'rb') as asl:
            acpi_bin.write(asl.read())

        acpi_bin.seek(ACPI_MCFG_ADDR_OFFSET)
        with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[3][1]), 'rb') as asl:
            acpi_bin.write(asl.read())

        acpi_bin.seek(ACPI_MADT_ADDR_OFFSET)
        with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[4][1]), 'rb') as asl:
            acpi_bin.write(asl.read())

        tpm2_enabled = common.get_node("//vm[@id = '0']/mmio_resources/TPM2/text()", scenario_etree)
        if tpm2_enabled is not None and tpm2_enabled == 'y':
            tpm2_node = common.get_node("//device[@id = 'MSFT0101']", board_etree)
            if tpm2_node is not None:
                tpm2_data_len = common.get_node("//table_length/text()", tpm2_node)
                _tpm2_data_len = 0
                has_log_area = False
                if tpm2_data_len is not None:
                    _tpm2_data_len = 76 if int(tpm2_data_len, 16) > 52 else 52
                    has_log_area = True if int(tpm2_data_len, 16) > 52 else False
                _data = bytearray(_tpm2_data_len)
                cytpe_data = tpm2_factory(12, has_log_area).from_buffer_copy(_data)
                cytpe_data.header.signature = "TPM2".encode()
                cytpe_data.header.revision = 0x3
                cytpe_data.header.oemid = "ACRN  ".encode()
                cytpe_data.header.oemtableid = "ACRNTPM2".encode()
                cytpe_data.header.oemrevision = 0x1
                cytpe_data.header.creatorid = "INTL".encode()
                cytpe_data.header.creatorrevision = 0x20190703
                cytpe_data.address_of_control_area = 0x00000000FED40040
                start_method_parameters = common.get_node("//parameter/text()", tpm2_node)
                if start_method_parameters is not None:
                    _parameters = bytearray.fromhex(str)
                    for i in range(len(_parameters)):
                        ctype_data.start_method_parameters[i] = _parameters[i].to_bytes(1, 'little')

                cytpe_data.header.revision = (~(sum(lib.cdata.to_bytes(cytpe_data))) + 1) & 0xFF
                acpi_bin.seek(ACPI_TPM2_ADDR_OFFSET)
                acpi_bin.write(lib.cdata.to_bytes(cytpe_data))

        acpi_bin.seek(ACPI_DSDT_ADDR_OFFSET)
        with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[6][1]), 'rb') as asl:
            acpi_bin.write(asl.read())

        if 'PTCT' in os.listdir(dest_vm_acpi_path):
            acpi_bin.seek(ACPI_RTCT_ADDR_OFFSET)
            with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[7][1]), 'rb') as asl:
                acpi_bin.write(asl.read())
        elif 'RTCT' in os.listdir(dest_vm_acpi_path):
            acpi_bin.seek(ACPI_RTCT_ADDR_OFFSET)
            with open(os.path.join(dest_vm_acpi_bin_path, ACPI_TABLE_LIST[8][1]), 'rb') as asl:
                acpi_bin.write(asl.read())

        acpi_bin.seek(0xfffff)
        acpi_bin.write(b'\0')
    shutil.move(acpi_bin_file, os.path.join(dest_vm_acpi_bin_path, '..', acpi_bin_name))
    print('write ACPI binary to {} successfully'.format(os.path.join(dest_vm_acpi_bin_path, '..', acpi_bin_name)))


def exec_command(cmd):
    '''
    execute the command and output logs.
    :param cmd: the command to execute.
    :return:
    '''
    print('exec: ', cmd)
    p_compile_result = r'Compilation successful. (\d+) Errors, (\d+) Warnings, (\d+) Remarks'
    cmd_list = cmd.split()
    rc = 1
    r_lines = []
    try:
        for line in subprocess.check_output(cmd_list).decode('utf8').split('\n'):
            r_lines.append(line)
            m = re.match(p_compile_result, line)
            if m and len(m.groups()) == 3:
                rc = int(m.groups()[0])
                break
    except Exception as e:
        print('exception when exec {}'.format(cmd), e)
        rc = -1

    if rc > 0:
        print('\n'.join(r_lines))

    return rc


def check_iasl():
    '''
    check iasl installed
    :return: True if iasl installed.
    '''
    try:
        p_version = 'ASL+ Optimizing Compiler/Disassembler version'
        min_version = 20190703
        output = subprocess.check_output(['iasl', '-v']).decode('utf8')
        if p_version in output:
            try:
                for line in output.split('\n'):
                    if line.find(p_version) >= 0:
                        version = int(line.split(p_version)[1].strip())
                        if version >= min_version:
                            return True
            except:
                pass
            return False
        elif 'command not found' in output:
            return False
        else:
            print(output)
            return False
    except Exception as e:
        print(e)
        return False


def main(args):

    board_type = args.board
    scenario_name = args.scenario
    board_path = os.path.join(VM_CONFIGS_PATH, 'data', board_type, board_type + '.xml')
    board_etree = lxml.etree.parse(board_path)
    scenario_path = os.path.join(VM_CONFIGS_PATH, 'data', board_type, scenario_name + '.xml')
    scenario_etree = lxml.etree.parse(scenario_path)
    if args.asl is None:
        DEST_ACPI_PATH = os.path.join(VM_CONFIGS_PATH, 'scenarios', scenario_name)
    else:
        DEST_ACPI_PATH = os.path.join(common.SOURCE_ROOT_DIR, args.asl, 'scenarios', scenario_name)
    if args.out is None:
        DEST_ACPI_BIN_PATH = os.path.join(common.SOURCE_ROOT_DIR, 'build', 'hypervisor', 'acpi')
    else:
        DEST_ACPI_BIN_PATH = args.out

    if os.path.isdir(DEST_ACPI_BIN_PATH):
        shutil.rmtree(DEST_ACPI_BIN_PATH)

    if not check_iasl():
        print("Please install iasl tool with version >= 20190703 from https://www.acpica.org/downloads before ACPI generation.")
        return 1

    for config in os.listdir(DEST_ACPI_PATH):
        if os.path.isdir(os.path.join(DEST_ACPI_PATH, config)) and config.startswith('ACPI_VM'):
            print('start to generate ACPI binary for {}'.format(config))
            dest_vm_acpi_path = os.path.join(DEST_ACPI_PATH, config)
            dest_vm_acpi_bin_path = os.path.join(DEST_ACPI_BIN_PATH, config)
            os.makedirs(dest_vm_acpi_bin_path)
            if asl_to_aml(dest_vm_acpi_path, dest_vm_acpi_bin_path):
                return 1
            aml_to_bin(dest_vm_acpi_path, dest_vm_acpi_bin_path, config+'.bin', board_etree, scenario_etree)

    return 0

if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage="python3 bin_gen.py --board [board] --scenario [scenario]"
                                           "[ --out [output dir of acpi ASL code]]",
                                     description="the tool to generate ACPI binary for Pre-launched VMs.")
    parser.add_argument("--board", required=True, help="the board type.")
    parser.add_argument("--scenario", required=True, help="the scenario name.")
    parser.add_argument("--asl", default=None, help="the input folder to store the ACPI ASL code. ")
    parser.add_argument("--out", default=None, help="the output folder to store the ACPI binary code. "
                                                    "If not specified, the path for the binary code is"
                                                    "build/acpi/")

    args = parser.parse_args()
    rc = main(args)
    sys.exit(rc)
