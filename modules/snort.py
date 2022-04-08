"""Modules that work with Snort data.
"""

import logging
from tabulate import tabulate

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer

class SplunkSnortAlertAnalysis(SplunkAPIAnalysis):
    """What are all the snort alerts for this ip address?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkSnortAlertsAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkSnortAlertAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            data = {key:value for (key,value) in row.items() if not key.startswith("_") or key == "_time"}
            primary_data.append(data)
        analysis.details['tables'][f"Snort Alerts with {observable.value}"] = tabulate(primary_data, headers='keys', tablefmt="psql")
        for result in primary_data:
            if result.get("name") and "SCAN" in result.get("name"):
                analysis.add_tag("Scanning Detected")
                observable.add_tag("suspect")
            if result.get("category", "") == "Potentially Bad Traffic":
                analysis.add_tag("Potentially Bad Traffic")
                observable.add_tag("suspect")
