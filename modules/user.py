"""Modules for user correlations.
"""

import logging
from tabulate import tabulate
import saq
from saq.email import is_local_email_domain
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer, GenericSplunkAPIAnalyzer, GenericSummaryTableForSplunkAPIAnalysis


class SplunkWindowsLogsActivityAnalysis(GenericSummaryTableForSplunkAPIAnalysis):
    pass

class SplunkWindowsLogsActivityAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_IPV4

    @property
    def generated_analysis_type(self):
        return SplunkWindowsLogsActivityAnalysis

    def process_finalize(self, analysis, observable) -> None:
        for row in analysis.details['query_results']:
            user = row.get('user_id')
            if not user:
                continue
            analysis.add_observable(F_USER, user)

class SplunkAzureActiveDirectoryInteractiveSignIn(GenericSummaryTableForSplunkAPIAnalysis):
    pass

class SplunkAzureActiveDirectoryInteractiveSignInAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    @property
    def generated_analysis_type(self):
        return SplunkAzureActiveDirectoryInteractiveSignIn

    def custom_requirement(self, observable):
        # only analyze our email addresses
        if not  is_local_email_domain(observable.value):
            logging.debug(f"{observable.value} is not a local email domain.")
            return False
        return True

class SplunkAzureActiveDirectoryNonInteractiveSignIn(GenericSummaryTableForSplunkAPIAnalysis):
    pass

class SplunkAzureActiveDirectoryNonInteractiveSignInAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    @property
    def generated_analysis_type(self):
        return SplunkAzureActiveDirectoryNonInteractiveSignIn

    def custom_requirement(self, observable):
        # only analyze our email addresses
        if not  is_local_email_domain(observable.value):
            logging.debug(f"{observable.value} is not a local email domain.")
            return False
        return True


""" DEPRECATED """
class SplunkAzureAD_Analysis(SplunkAPIAnalysis):
    @property
    def jinja_template_path(self):
        return "analysis/generic_summary_tables.html"

    def generate_summary_tables(self):
        if 'query_results' not in self.details:
            return None
        results = self.details['query_results']
        summary_table_data = [{key:value for key,value in event.items()} for event in results]
        tables = {"Summary of Azure Active Directory Activity": tabulate(summary_table_data, headers='keys')}
        return tables

class SplunkAzureActiveDirectoryAuditAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkAzureAD_Analysis

    @property
    def valid_observable_types(self):
        return F_EMAIL_ADDRESS

    def custom_requirement(self, observable):
        if not  is_local_email_domain(observable.value):
            logging.debug(f"{observable.value} is not a local email domain.")
            return False
        return True


