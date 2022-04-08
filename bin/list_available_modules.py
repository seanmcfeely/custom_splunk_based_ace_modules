#!/usr/bin/env python3

import configparser

config = configparser.ConfigParser()
config.read('etc/saq.splunkmods.default.ini')

analysis_modules = [s for s in config if s.startswith('analysis_module_')]

print("Analysis Module Name: Analysis Module Description/Question")
print("----------------------------------------------------------")
for am in analysis_modules:
    print(f"{am}:\t{config[am]['question']}")
