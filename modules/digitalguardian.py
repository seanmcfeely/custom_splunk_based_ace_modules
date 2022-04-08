"""Modules that work with Digital Guardian data.
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

class SplunkDGprocessHashAnalysis(SplunkAPIAnalysis):
    """How many assets have executed a program with this hash value?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkDGprocessHashAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkDGprocessHashAnalysis

    @property
    def valid_observable_types(self):
        return F_MD5

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            data = {key:value for (key,value) in row.items() if not key.startswith("_") or key == "_time"}
            primary_data.append(data)
        analysis.details['tables']["Process Execution Summary"] = tabulate(primary_data, headers='keys', tablefmt="psql")


class SplunkDgUSBActivityAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_HOSTNAME
