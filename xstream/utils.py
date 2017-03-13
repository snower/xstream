# -*- coding: utf-8 -*-
# 17/3/13
# create by: snower

def format_data_len(data_len):
    if data_len < 1024:
        return "%dB" % data_len
    elif data_len < 1024 * 1024:
        return "%.3fK" % (data_len / 1024.0)
    elif data_len < 1024 * 1024 * 1024:
        return "%.3fM" % (data_len / (1024.0 * 1024.0))