#!/usr/bin/env python3
#
# Copyright (C) 2021 Intel Corporation.
#
# SPDX-License-Identifier: BSD-3-Clause
#

import sys, os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'library'))
import common

def fn(board_etree, scenario_etree, allocation_etree):
    msi_count = board_etree.xpath("//capability[@id = 'MSI']/count/text()")
    msix_table_size = board_etree.xpath("//capability[@id = 'MSI-X']/table_size/text()")
    table = [int(i) for i in msi_count + msix_table_size]
    max_msix_table_num = 64
    try:
        max_msix_table_num = max(table)
    except:
        common.print_yel("Cannot find the MSI counts and MSI-X table_siz from board xml, MAX_MSIX_TABLE_NUM sets to default value 64.", warn=True)
        pass
    common.append_node("/acrn-config/hv/MAX_MSIX_TABLE_NUM", str(max_msix_table_num), allocation_etree)