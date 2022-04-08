"""Modules that work with email logs.
"""

import os
import logging
from tabulate import tabulate

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer

KEY_EMAILS = 'query_results'

class EmailHistoryRecord(object):
    """Utility class to add extra fields not present in the splunk logs."""

    def __init__(self, details):
        self.details = details
    
    def __getitem__(self, key):
        return self.details[key]

    @property
    def md5(self):
        file_name = os.path.basename(self.details['archive_path'])
        md5, ext = os.path.splitext(file_name)
        return md5

class SplunkEmailHistoryAnalysis(SplunkAPIAnalysis):
    """How many emails did this user receive?  What is the general summary of them?"""
    @property
    def emails(self):
        if not self.details:
            return []

        if not self.details[KEY_EMAILS]:
            return []
        
        return [EmailHistoryRecord(email) for email in self.details[KEY_EMAILS]]

    @emails.setter
    def emails(self, value):
        assert value is None or isinstance(value, list)
        self.details[KEY_EMAILS] = value

    @property
    def jinja_template_path(self):
        return 'analysis/email_history_v2.html'
        #return "analysis/generic_api_tables.html"

class SplunkEmailHistoryAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkEmailHistoryAnalysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    #def process_finalize(self, analysis, observable) -> None:
    #    primary_data = []
    #    for row in analysis.details['query_results']:
    #        data = {key:value for (key,value) in row.items() if not key.startswith("_") or key == "_time"}
    #        primary_data.append(data)
    #    analysis.details['tables'][f"Email Summary for {observable.value}"] = tabulate(primary_data, headers='keys', tablefmt="psql")
