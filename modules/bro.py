"""Modules for ZEEK data.

The company formally known as BRO.
"""

import re
import logging
from tabulate import tabulate

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer, GenericSplunkAPIAnalyzer

class SplunkBroKerberosActivityAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_IPV4

    def process_finalize(self, analysis, observable) -> None:
        for row in analysis.details['query_results']:
            data = {}
            client = row.get('client')
            if not client:
                continue

            client = client[:client.rfind('/')] if '/' in client else client
            user = re.findall(r'^\w\d{6}$', client)
            if user and isinstance(user, list):
                analysis.add_observable(F_USER, user[0])
            host = re.findall(r'^[A-Za-z]{9,11}\d{1,3}\-?\d?', client)
            if host and isinstance(host, list):
                analysis.add_observable(F_HOSTNAME, host[0])

class SplunkBroIpConvoCorrelationAnalysis(SplunkAPIAnalysis):
    """Given dest+src+src_port, what did our Bro/Zeek sensors record?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkBroIpConvoAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkBroIpConvoCorrelationAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4_FULL_CONVERSATION

    @property
    def summary_fields(self):
        return self.config.get('summary_fields', "").split(',')

    def custom_requirement(self, observable):
        # custom format the query value
        src_ip, src_port, dest_ip, dest_port = parse_ipv4_full_conversation(observable.value)
        updated_query_value = f"{src_ip} {src_port} {dest_ip} {dest_port}"
        self.target_query = self.target_query.replace('<O_VALUE>', updated_query_value)
        return True

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            data = {}
            for field in self.summary_fields:
                data[field] = row.get(field)
                if field == 'user_agent' and data[field] and data[field] != '-':
                    analysis.add_observable("user_agent", data[field])
                if field == 'dest_host' and data[field] and data[field] != '-':
                    analysis.add_observable(F_FQDN, data[field])
                if field == 'status_code' and data[field] == '200':
                    observable.add_tag("status_code:200")
                if field == 'proxied' and data.get(field):
                    proxied_ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', data[field])
                    for ipv4 in proxied_ips:
                        analysis.add_observable(F_IPV4, ipv4)
            primary_data.append(data)
        analysis.details['tables']["Bro Log Summary"] = tabulate(primary_data, headers='keys', tablefmt="psql")


class SplunkBroIPv4LookupAnalysis(SplunkAPIAnalysis):
    """Given dest+src+src_port, what did our Bro/Zeek sensors record?"""
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkBroIpLookup(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkBroIPv4LookupAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    @property
    def summary_fields(self):
        return self.config.get('summary_fields', "").split(',')

    def custom_requirement(self, observable):
        if observable.type == F_IPV4 and observable.is_managed():
            # we don't analyze our own IP address space.
            logging.debug(f"{self} skipping {self} for managed or private ipv4 {observable}")
            return False
        if observable not in self.root.observables:
            logging.debug(f"{self} skipping {observable} because it didn't come with the alert.")
            return False
        return True

    def process_finalize(self, analysis, observable) -> None:
        primary_data = []
        for row in analysis.details['query_results']:
            data = {}
            for field in self.summary_fields:
                data[field] = row.get(field)
                if field == 'user_agent' and data[field] and data[field] != '-':
                    analysis.add_observable("user_agent", data[field])
                if field == 'dest_host' and data[field] and data[field] != '-':
                    analysis.add_observable(F_FQDN, data[field])
                if field == 'status_code' and data[field] == '200':
                    observable.add_tag("status_code:200")
            primary_data.append(data)
        analysis.details['tables']["Bro Log Summary"] = tabulate(primary_data, headers='keys', tablefmt="psql")