"""Modules for Palo Alto Networks data.
"""

import logging
from tabulate import tabulate

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer


class SplunkPANthreatsAnalysis(SplunkAPIAnalysis):
    """What are the PaloAlto alerts for this ip address?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkPANthreatsAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkPANthreatsAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            data = {key:value for (key,value) in row.items() if not key.startswith("_") or key == "_time"}
            primary_data.append(data)
        analysis.details['tables']["Palo Alto Network Threat Summary"] = tabulate(primary_data, headers='keys', tablefmt="psql")


class SplunkPanSnortCorrelationAnalysis(SplunkAPIAnalysis):
    """Given a snort alert and dest+src+src_port, what PAN blocks did we see around the same time?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkPanSnortCorrelationAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkPanSnortCorrelationAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4_FULL_CONVERSATION

    def custom_requirement(self, observable):
        if self.root.alert_type != 'hunter - splunk - snort':
            logging.debug(f"{self} only works on splunk based snort alerts: {self.root.alert_type}")
            return False

        # custom format the query value
        src_ip, src_port, dest_ip, dest_port = parse_ipv4_full_conversation(observable.value)
        updated_query_value = f"{src_ip} AND {dest_ip} AND src_port={src_port}"
        self.target_query = self.target_query.replace('<O_VALUE>', updated_query_value)
        return True

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            data = {key:value for (key,value) in row.items() if not key.startswith("_") or key == "_time"}
            primary_data.append(data)
        analysis.details['tables']["Snort-PAN Threat Summary"] = tabulate(primary_data, headers='keys', tablefmt="psql")