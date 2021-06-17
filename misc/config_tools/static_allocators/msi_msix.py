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
    common.append_node("/acrn-config/hv/MAX_MSIX_TABLE_NUM", str(max(table)), allocation_etree)