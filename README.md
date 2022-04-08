# Custom Splunk Modules for ACE

This repo contains splunk based ACE modules that have been custom tailored for different environments. All of these modules utilize the SplunkAPIAnalysis module in ACE. This means the splunk integration must be already configured and working for ACE.


# Project Breakdown

## modules directory

The `modules` directory contains the module code. In your ACE instance, it's recommended that these go inside of a dedicated directory named `splunkmods` at the following location::

    $SAQ_HOME/saq/modules/splunkmods/

The above directory should be ignored in the ACE .gitignore file.

Finally, multiple modules may be in the same file; the modules are loosely organized into the file names that best describe their feature/functionality/use case/etc.

### Example Symlink SplunkMods

```bash
 mkdir /opt/ace/saq/modules/splunkmods
 ln -s /opt/custom_splunk_based_ace_modules/modules/* /opt/ace/saq/modules/splunkmods/.
```

## etc directory

Next, the `etc` dir contains the default configuration file(s) for the Splunk modules found in `modules`. The default config file is at::

    etc/saq.splunkmods.default.ini

All of the modules are disabled by default and they all assume that the module is found at the recommended `splunkmods` path.

Additionally, all of the modules are included into the correlation module group by default.

## bin directory

There is a bin script to list out the currently configure modules. Example:

```bash 
$ bin/list_available_modules.py 
Analysis Module Name: Analysis Module Description/Question
----------------------------------------------------------
analysis_module_cbc_log_analysis:	What do we know about this process?
analysis_module_bro_kerberos_analysis:	Has any kerberos activity been associated to this IPv4?
analysis_module_winlogs_activity_analyzer:	Was a user associated to this IPv4 in Windows logs?
analysis_module_user_azure_ad_history_analyzer:	What do the Azure AD audit logs say about this UPN?
analysis_module_user_azure_sign_in_history_analyzer:	"What does this user's interactive authentication history look like?"
analysis_module_user_non_interactive_azure_sign_in_history_analyzer:	"What does this user's non-interactive authentication history look like?"
analysis_module_email_history_analyzer:	How many emails did this user receive? What is the general summary of them?
analysis_module_snort_ip_analysis:	What are all the snort alerts for this ip address?
analysis_module_dg_dlp_process_hash_analysis:	How many assets and users have executed a program with this hash value in the past N hours?
analysis_module_dg_usb_analysis:	Has Digital Guardian observed any recent USB activiy on this host?
analysis_module_cisco_asa_client_vpn_ip:	What user had this VPN IP address assigned at this time?
analysis_module_symantec_analyzer:	Did Symantec detect anything on this asset?
analysis_module_pan_threats:	What are the PaloAlto alerts for this ip address?
analysis_module_bro_ipv4_conversation_analyzer:	What does Bro/Zeek show for this IPv4 network connection?
analysis_module_bro_ipv4_lookup:	What does Bro/Zeek show for this external IPv4 around this time?
analysis_module_pan_snort_correlation:	What PAN threats did we see around the same time as this snort alert?
```

# Turn on the SplunkMods ACE Integration

After you've symlinked your modules and you configuration files, you need to turn on the integration in ACE. 

Symlink default config:
```bash
ln -s /opt/custom_splunk_based_ace_modules/etc/saq.splunkmods.default.ini /opt/ace/etc/.
```
ACE should now be able to see it:
```bash
$ ace integration list | grep splunk
splunk              yes       
splunkmods          no     
```

Turn it on:
```bash 
$ ace integration enable splunkmods
splunkmods enabled
```

If you have a custom splunkmods override ready from a site repo:
```
ln -s /opt/site/opt/ace/etc/saq.splunkmods.ini /opt/ace/etc/.
```

Now, rebuild your ACE Engine Docker service and `ace verify-modules`.

# How To

Check out [this page](docs/create_new_module.md) for a guide on creating a simple module.

# Module Structure Example

The following file::

    modules/user.py 

Contains this module:

```python
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
```

Which corresponds to this section in the `etc/saq.splunkmods.default.ini`:

```
[analysis_module_cisco_asa_client_vpn_ip]
; This module correlates users from known VPN IPv4 networks
; when using Cisco ASA for VPN. The code creates email_address
; observables but that may need to be a user observable or ...
module=saq.modules.splunkmods.user
class=SplunkCiscoASAClientVPNAnalyzer
enabled=no
question=What user had this VPN IP address assigned at this time?
summary=Client VPN Analysis
api=splunk
use_index_time=no
max_result_count=10
narrow_duration_before = 00:10:00
narrow_duration_after = 00:10:00
query=index=vpn_clients <O_TIMESPEC> <O_VALUE> | dedup user
# comma seperated list of vpn networks (CIDR format)
vpn_networks=
```

You can use the above by copying the config section to a config in your SAQ_CONFIG_PATHS environment variable and configuring it as you require. Of course, the `$SAQ_HOME/saq/modules/splunkmods/user.py` has to exist with the code.

    