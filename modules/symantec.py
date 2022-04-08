"""Modules that work with Symantec data.
"""

import logging
import pytz
from tabulate import tabulate

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer, GenericSplunkAPIAnalyzer

class SplunkSymantecHostUSBAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    def process_splunk_event(self, analysis, observable, event, event_time):
        device_id = event.get('Device_ID')
        if device_id:
            analysis.add_observable('usb_device_id', device_id)
            observable.add_tag("usb_discovered")

class SplunkSymantecAnalysis(SplunkAPIAnalysis):
    def initialize_details(self, *args, **kwargs):
        super().initialize_details(*args, **kwargs)
        self.details.update({
                'categories': {},
                'tables': {},
        })

    @property
    def jinja_template_path(self):
        return "analysis/generic_api_tables.html"

class SplunkSymantecAnalyzer(SplunkAPIAnalyzer):
    @property
    def generated_analysis_type(self):
        return SplunkSymantecAnalysis

    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    def custom_requirement(self, observable):
        # custom queries per observable type
        if observable.type == F_FQDN:
            logging.debug("updating query to work with fqdn")
            self.target_query = self.config['fqdn_query']

        elif observable.type == F_FILE_PATH:
            logging.debug("updating query to work with file_path")
            self.target_query = self.config['file_path_query']
            # go ahead and replace <O_VALUE> so we can escape it
            _escape_value = observable.value.replace('\\', '\\\\')
            self.target_query = self.target_query.replace('<O_VALUE>', _escape_value)

        # else the default works with F_HOSTNAME
        return True

    def process_splunk_event(self, analysis, observable, event, event_time):
        signature = event['signature']
        if ':' in signature and len(signature) > 20:
            signature = signature[:signature.find(':')]
        observable.add_tag(f"av:{signature}")

        if event['sourcetype'] not in analysis.details['categories']:
            analysis.details['categories'][event['sourcetype']] = []

        category_fields = {}
        for key, value in event.items():
            if key != '_time' and key.startswith('_'):
                continue
            if value:
                category_fields[key] = value

        analysis.details['categories'][event['sourcetype']].append(category_fields)

    def process_finalize(self, analysis, observable) -> None:
        for category in analysis.details['categories'].keys():
            analysis.details['tables'][f"Summary of sourcetype='{category}'"] = tabulate(analysis.details['categories'][category], headers='keys', tablefmt="psql")
