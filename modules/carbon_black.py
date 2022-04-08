"""Modules that work with Carbon Black data.
"""

import logging
import pytz
from tabulate import tabulate

import saq
from saq.constants import *
from saq.modules.splunk import (
    GenericSplunkAPIAnalyzer,
    SplunkAPIAnalysis,
    SplunkAPIAnalyzer
)


class SplunkCbcProcessGUIDAnalysis(SplunkAPIAnalysis):
    """How many assets have executed a program with this hash value?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'parent': {},
                'process': {},
                'childprocs': [],
                'device': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/splunk_cbc_process_guid.html"

class SplunkCbcProcessGUIDAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkCbcProcessGUIDAnalysis

    @property
    def valid_observable_types(self):
        return F_CBC_PROCESS_GUID

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            # if there are more than one event, we have childprocess events.
            # parent and process fields should be the same for every event.
            child_process_data = {}
            for key, value in row.items():
                if key.startswith("_"):
                    continue
                if key.startswith("parent_"):
                    if key not in analysis.details['parent']:
                        analysis.details['parent'][key] = value
                    if key == "parent_cmdline":
                        _o = analysis.add_observable("command_line", value)
                        _o.add_tag("parent_cmdline")
                    continue
                if key.startswith("device_"):
                    if key not in analysis.details['device']:
                        analysis.details['device'][key] = value
                    continue
                if key.startswith("process_"):
                    if key not in analysis.details['process']:
                        analysis.details['process'][key] = value
                    if key == "process_cmdline":
                        _o = analysis.add_observable("command_line", value)
                        _o.add_tag("process_cmdline")
                    continue
                if key.startswith("childproc_") or key == "target_cmdline":
                    if key not in child_process_data:
                        child_process_data[key] = value
                    continue
            if child_process_data:
                analysis.details["childprocs"].append(child_process_data)