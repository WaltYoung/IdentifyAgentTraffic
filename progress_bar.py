#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Xiao'

import sys

def progress_bar(progress, iteration, total, length=50):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    if eval(percent) >= 100:
        percent = 100.0
        filled_length = length
    bar = '█' * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{progress}: |{bar}| {percent}%')
    sys.stdout.flush()  # 刷新输出以确保进度条实时更新
    if iteration == total:
        print()