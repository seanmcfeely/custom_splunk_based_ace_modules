# Creating new splunkmod

# Use case

One of our analyst commonly uses the following Splunk query when investigating Symantec AV alerts to determine if any USB devices were inserted/being used on a host:

`index=av* FAKE001Host7 USB`

# Code

First, we decided what file this module code should go in. There is already a symantec.py file so lets use that one.

Now, here I will highlight a custom `GenericSplunkAPIAnalyzer` class that is perfect for simply adding Splunk results to ACE when you do not need to do any further analysis with python. We will use this class by making sure it's imported at the top of symantec.py:

```python 
"""Modules that work with Symantec data.
"""

import logging

import saq
from saq.constants import *
from saq.modules.splunk import SplunkAPIAnalysis, SplunkAPIAnalyzer, GenericSplunkAPIAnalyzer
```

Next, we define our code like this (the class name has to be unique and it should have a sensible and descriptive name!):

```python
class SplunkSymantecHostUSBAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_HOSTNAME
```

That's all we need for now. Let's set up the config next.

# Config Setup

Next, add the following to the `saq.splunkmods.default.ini` config file to set the defaults for this module:

The analysis module name has to be unique! 

```
[analysis_module_symantec_usb_analysis]
maximum_analysis_time = 30
module=saq.modules.splunkmods.symantec
class=SplunkSymantecHostUSBAnalyzer
enabled=no
question=Has Symantec observed any recent USB activiy on this host?
summary=Symantec USB Activity Analysis
api=splunk
use_index_time=no
max_result_count=500
wide_duration_before = 168:00:00
wide_duration_after = 04:00:00
narrow_duration_before = 24:00:00
narrow_duration_after = 00:15:00
query = index=av* <O_TIMESPEC> <O_VALUE> USB | search hostname=<O_VALUE> Device_ID="*USB*" | fields _time, Begin_Time, Device_ID, user, API, process, Parameter
```

Now, enabled the above module in you override config so we can test it. Add the following to your override config:

Our override config at the time of writing is symlinked in /opt/ace at `etc/saq.splunkmods.ini`:

```
[analysis_module_symantec_usb_analysis]
enabled = yes
```

# Test the Module

Rebuild the ACE engine container you're working with (hopefully you're not doing this in prod):

`cybersecurity@ace-qa:/opt/ace$ bin/rebuild-and-start-ace-engine.sh`

Next, `$ bin/drop-in-ace-engine.sh ` and once inside the container verify modules

`ace verify-modules`

If you seen an error then something went wrong and you need to fix it.

The following tells us our module verified:

```bash
$ ace verify-modules 2>&1 | grep symantec_usb_analysis
[INFO] analysis module analysis_module_symantec_usb_analysis verification OK
```

Now we can execute the module with ACE to test it's execution. The following command tell ACE we want to correlate this hostname with all analysis modules disable except out new new on and we want to set the reference time to 2022-03-23 18:40:39.

```bash
ace correlate hostname FAKE001Host7 --disable-all -E symantec_usb_analysis -t '2022-03-23 18:40:39'
```

Here is the execution with some logging noise piped to /dev/null for the sake of brevity in this document.

```bash
$ ace correlate hostname FAKE001Host7 --disable-all -E symantec_usb_analysis -t '2022-03-23 18:40:39' 2>/dev/null
ACE Manual Correlation
 * hostname:FAKE001Host7 @ 2022-03-23 18:40:39+00:00
	Symantec USB Activity Analysis: (46 results)
```

We can import the above analysis into the ACE GUI by importing the analysis as an alert:

```bash
$ ace import-alerts data/ace.out/
[INFO] rebuilding indexes for RootAnalysis(7e6cbfb0-36c3-4195-9763-eedd87b3faa3)
[INFO] added 7e6cbfb0-36c3-4195-9763-eedd87b3faa3 to workload with analysis mode correlation company_id 1 exclusive_uuid None
[INFO] imported alert RootAnalysis(7e6cbfb0-36c3-4195-9763-eedd87b3faa3)
```

We've successfully added a splunk based correlation module to ACE. 

# Adding Observables and Tags

Now say we've decided we want to add an observable for the USB device we may find in this module and also tag the analysis if we find a USB device. I've done that in the below code and updated it in the splunkmods/splunk.py file.

```python
class SplunkSymantecHostUSBAnalyzer(GenericSplunkAPIAnalyzer):
    @property
    def valid_observable_types(self):
        return F_HOSTNAME

    def process_splunk_event(self, analysis, observable, event, event_time):
        device_id = event.get('Device_ID')
        if device_id:
            analysis.add_observable('usb_device_id', device_id)
            observable.add_tag("usb_discovered")
```

Now rebuild the ACE Engine container, drop into the container, and test the module again. 

```bash
$ ace correlate hostname FAKE001Host7 --disable-all -E symantec_usb_analysis -t '2022-03-23 18:40:39' 2>/dev/null
ACE Manual Correlation
 * hostname:FAKE001Host7 @ 2022-03-23 18:40:39+00:00 [ usb_discovered ] 
	Symantec USB Activity Analysis: (46 results)
	 * usb_device_id:USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Force&Rev_1.00\00000506101620031314&0
1 TAGS
* usb_discovered
```

The above shows that the tag ans USB device ID was added as expected to the analysis.

