"""Modules that work with cisco logs.
"""

import logging
import pytz

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer

from iptools import IpRange

class SplunkCiscoASAClientVPNAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkAPIAnalysis

    @property
    def valid_observable_types(self):
        return F_IPV4

    @property
    def vpn_networks(self):
        return self.config['vpn_networks'].split(',')

    def custom_requirement(self, observable):
        # only work on IPv4 observable that belong to a vpn network
        for cidr in self.vpn_networks:
            cidr_object = IpRange(cidr)
            if observable.value in cidr_object:
                return True
        logging.debug(f"not using {self}: {observable.value} is not a known VPN address.")
        return False

    def process_splunk_event(self, analysis, observable, event, event_time):
        if 'user' in event and event['user']:
            analysis.add_observable(F_EMAIL_ADDRESS, event['user'].lower())