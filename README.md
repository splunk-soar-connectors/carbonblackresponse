[comment]: # "Auto-generated SOAR connector documentation"
# Carbon Black Response

Publisher: Splunk  
Connector Version: 2\.3\.3  
Product Vendor: Bit9  
Product Name: Carbon Black  
Product Version Supported (regex): "\[5\-7\]\\\.\[0\-9\]\\\.\*"  
Minimum Product Version: 4\.10\.0\.40961  

This app supports executing various endpoint\-based investigative and containment actions on Carbon Black Response

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "  Licensed under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)"
[comment]: # ""
Every action uses the **api_token** configured on the Carbon Black Response asset. This token
represents a user on the Carbon Black Response server. Many actions like **list endpoints** require
the user to have permissions to be able to view sensors. The Carbon Black Response user that Phantom
uses must have the privileges needed to perform the actions being attempted. For example, to
quarantine endpoints, the account used by Phantom must have Carbon Black Response administrator
privileges.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Carbon Black asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device\_url** |  required  | string | Device URL, e\.g\. https\://mycb\.enterprise\.com
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**api\_token** |  required  | password | API Token

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration by attempting to connect\. This action runs a quick query on the device to check the connection and credentials  
[hunt file](#action-hunt-file) - Hunt for a binary file on the network by querying for the MD5 hash of it on the Carbon Black Response device\. This utilizes Carbon Black Response's binary search feature to look for files on the hard drives of endpoints  
[create alert](#action-create-alert) - Create an alert/watchlist  
[update alerts](#action-update-alerts) - Update or resolve an alert  
[run query](#action-run-query) - Run a search query on the device  
[list alerts](#action-list-alerts) - List all the alerts/watchlists configured on the device  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[quarantine device](#action-quarantine-device) - Quarantine the endpoint  
[unquarantine device](#action-unquarantine-device) - Unquarantine the endpoint  
[sync events](#action-sync-events) - Force a sensor to sync all queued events to the server  
[get system info](#action-get-system-info) - Get information about an endpoint  
[list processes](#action-list-processes) - List the running processes on a machine  
[terminate process](#action-terminate-process) - Kill running processes on a machine  
[get file](#action-get-file) - Download a file from Carbon Black Response and add it to the vault  
[put file](#action-put-file) - Upload file to a Windows hostname  
[run command](#action-run-command) - Issue a Carbon Black Response command by providing the command name and the command's parameters as the 'data'  
[execute program](#action-execute-program) - Execute a process  
[memory dump](#action-memory-dump) - Memory dump for a specified path  
[reset session](#action-reset-session) - Tell the server to reset the sensor "sensor\_wait\_timeout"  
[get file info](#action-get-file-info) - Get info about a file from Carbon Black Response  
[block hash](#action-block-hash) - Add a hash to the Carbon Black Response blacklist  
[unblock hash](#action-unblock-hash) - Unblock the hash  
[list connections](#action-list-connections) - List all of the connections from a given process name, PID, or Carbon Black process ID  
[on poll](#action-on-poll) - Ingests unresolved alerts into Phantom  
[get license](#action-get-license) - Gets the license information of the device  

## action: 'test connectivity'
Validate the asset configuration by attempting to connect\. This action runs a quick query on the device to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'hunt file'
Hunt for a binary file on the network by querying for the MD5 hash of it on the Carbon Black Response device\. This utilizes Carbon Black Response's binary search feature to look for files on the hard drives of endpoints

Type: **investigate**  
Read only: **True**

This action gives back paginated results\. The 'range' parameter can be used to control the number and indexes of the search results\.<br>This action requires only a Carbon Black Response <b>api\_token</b>\. The Carbon Black Response user assigned to that token does not require any privileges \(i\.e\. No Access\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | MD5 of the binary or process to hunt | string |  `hash`  `md5` 
**type** |  required  | Type of search | string |  `carbon black query type` 
**range** |  optional  | Range of items to return, for e\.g\. 0\-10 | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `hash`  `md5` 
action\_result\.parameter\.range | string | 
action\_result\.parameter\.type | string |  `carbon black query type` 
action\_result\.data\.\*\.binary\.elapsed | numeric | 
action\_result\.data\.\*\.binary\.facets\.alliance\_score\_virustotal\.\*\.name | numeric | 
action\_result\.data\.\*\.binary\.facets\.alliance\_score\_virustotal\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.company\_name\_facet\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.company\_name\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.company\_name\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.company\_name\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.digsig\_publisher\_facet\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.digsig\_publisher\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.digsig\_publisher\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.digsig\_publisher\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.digsig\_result\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.digsig\_result\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.digsig\_result\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.digsig\_result\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.digsig\_sign\_time\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.digsig\_sign\_time\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.file\_version\_facet\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.file\_version\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.file\_version\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.file\_version\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.group\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.group\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.group\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.group\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.host\_count\.\*\.name | numeric | 
action\_result\.data\.\*\.binary\.facets\.host\_count\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.hostname\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.hostname\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.hostname\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.hostname\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.observed\_filename\_facet\.\*\.name | string |  `file path`  `file name` 
action\_result\.data\.\*\.binary\.facets\.observed\_filename\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.observed\_filename\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.observed\_filename\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.product\_name\_facet\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.product\_name\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.binary\.facets\.product\_name\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.binary\.facets\.product\_name\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.facets\.server\_added\_timestamp\.\*\.name | string | 
action\_result\.data\.\*\.binary\.facets\.server\_added\_timestamp\.\*\.value | numeric | 
action\_result\.data\.\*\.binary\.highlights\.\*\.ids | string |  `md5` 
action\_result\.data\.\*\.binary\.highlights\.\*\.name | string | 
action\_result\.data\.\*\.binary\.results\.\*\.alliance\_data\_srstrust | string |  `md5` 
action\_result\.data\.\*\.binary\.results\.\*\.alliance\_link\_srstrust | string |  `url` 
action\_result\.data\.\*\.binary\.results\.\*\.alliance\_score\_srstrust | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.alliance\_updated\_srstrust | string | 
action\_result\.data\.\*\.binary\.results\.\*\.cb\_version | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.company\_name | string | 
action\_result\.data\.\*\.binary\.results\.\*\.copied\_mod\_len | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_issuer | string | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_prog\_name | string | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_publisher | string | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_result | string | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_result\_code | string | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_sign\_time | string | 
action\_result\.data\.\*\.binary\.results\.\*\.digsig\_subject | string | 
action\_result\.data\.\*\.binary\.results\.\*\.endpoint | string | 
action\_result\.data\.\*\.binary\.results\.\*\.event\_partition\_id | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.facet\_id | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.file\_desc | string | 
action\_result\.data\.\*\.binary\.results\.\*\.file\_version | string | 
action\_result\.data\.\*\.binary\.results\.\*\.group | string | 
action\_result\.data\.\*\.binary\.results\.\*\.host\_count | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.internal\_name | string |  `file name` 
action\_result\.data\.\*\.binary\.results\.\*\.is\_64bit | boolean | 
action\_result\.data\.\*\.binary\.results\.\*\.is\_executable\_image | boolean | 
action\_result\.data\.\*\.binary\.results\.\*\.last\_seen | string | 
action\_result\.data\.\*\.binary\.results\.\*\.legal\_copyright | string | 
action\_result\.data\.\*\.binary\.results\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.binary\.results\.\*\.observed\_filename | string |  `file path`  `file name` 
action\_result\.data\.\*\.binary\.results\.\*\.orig\_mod\_len | numeric | 
action\_result\.data\.\*\.binary\.results\.\*\.original\_filename | string |  `file name` 
action\_result\.data\.\*\.binary\.results\.\*\.os\_type | string | 
action\_result\.data\.\*\.binary\.results\.\*\.product\_name | string | 
action\_result\.data\.\*\.binary\.results\.\*\.product\_version | string | 
action\_result\.data\.\*\.binary\.results\.\*\.server\_added\_timestamp | string | 
action\_result\.data\.\*\.binary\.results\.\*\.signed | string | 
action\_result\.data\.\*\.binary\.results\.\*\.timestamp | string | 
action\_result\.data\.\*\.binary\.results\.\*\.watchlists\.\*\.value | string | 
action\_result\.data\.\*\.binary\.results\.\*\.watchlists\.\*\.wid | string | 
action\_result\.data\.\*\.binary\.start | numeric | 
action\_result\.data\.\*\.binary\.terms | string | 
action\_result\.data\.\*\.binary\.total\_results | numeric | 
action\_result\.data\.\*\.process\.all\_segments | boolean | 
action\_result\.data\.\*\.process\.comprehensive\_search | boolean | 
action\_result\.data\.\*\.process\.elapsed | numeric | 
action\_result\.data\.\*\.process\.facets\.day\_of\_week\.\*\.name | numeric | 
action\_result\.data\.\*\.process\.facets\.day\_of\_week\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.group\.\*\.name | string | 
action\_result\.data\.\*\.process\.facets\.group\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.group\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.group\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.host\_type\.\*\.name | string | 
action\_result\.data\.\*\.process\.facets\.host\_type\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.host\_type\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.host\_type\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.hostname\.\*\.name | string | 
action\_result\.data\.\*\.process\.facets\.hostname\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.hostname\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.hostname\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.hour\_of\_day\.\*\.name | numeric | 
action\_result\.data\.\*\.process\.facets\.hour\_of\_day\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.parent\_name\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.process\.facets\.parent\_name\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.parent\_name\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.parent\_name\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.path\_full\.\*\.name | string |  `file path`  `file name` 
action\_result\.data\.\*\.process\.facets\.path\_full\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.path\_full\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.path\_full\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.process\_md5\.\*\.name | string |  `md5` 
action\_result\.data\.\*\.process\.facets\.process\_md5\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.process\_md5\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.process\_md5\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.process\_name\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.process\.facets\.process\_name\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.process\_name\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.process\_name\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.start\.\*\.name | string | 
action\_result\.data\.\*\.process\.facets\.start\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.facets\.username\_full\.\*\.name | string | 
action\_result\.data\.\*\.process\.facets\.username\_full\.\*\.percent | numeric | 
action\_result\.data\.\*\.process\.facets\.username\_full\.\*\.ratio | string | 
action\_result\.data\.\*\.process\.facets\.username\_full\.\*\.value | numeric | 
action\_result\.data\.\*\.process\.incomplete\_results | boolean | 
action\_result\.data\.\*\.process\.results\.\*\.alliance\_data\_srstrust | string |  `md5` 
action\_result\.data\.\*\.process\.results\.\*\.alliance\_link\_srstrust | string |  `url` 
action\_result\.data\.\*\.process\.results\.\*\.alliance\_score\_srstrust | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.alliance\_updated\_srstrust | string | 
action\_result\.data\.\*\.process\.results\.\*\.childproc\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.cmdline | string |  `file path` 
action\_result\.data\.\*\.process\.results\.\*\.comms\_ip | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.crossproc\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.emet\_config | string | 
action\_result\.data\.\*\.process\.results\.\*\.emet\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.filemod\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.filtering\_known\_dlls | boolean | 
action\_result\.data\.\*\.process\.results\.\*\.group | string | 
action\_result\.data\.\*\.process\.results\.\*\.host\_type | string | 
action\_result\.data\.\*\.process\.results\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.process\.results\.\*\.id | string |  `carbon black process id` 
action\_result\.data\.\*\.process\.results\.\*\.interface\_ip | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.last\_server\_update | string | 
action\_result\.data\.\*\.process\.results\.\*\.last\_update | string | 
action\_result\.data\.\*\.process\.results\.\*\.modload\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.netconn\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.os\_type | string | 
action\_result\.data\.\*\.process\.results\.\*\.parent\_id | string | 
action\_result\.data\.\*\.process\.results\.\*\.parent\_md5 | string | 
action\_result\.data\.\*\.process\.results\.\*\.parent\_name | string |  `file name` 
action\_result\.data\.\*\.process\.results\.\*\.parent\_pid | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.parent\_unique\_id | string | 
action\_result\.data\.\*\.process\.results\.\*\.path | string |  `file path`  `file name` 
action\_result\.data\.\*\.process\.results\.\*\.process\_md5 | string |  `md5` 
action\_result\.data\.\*\.process\.results\.\*\.process\_name | string |  `process name`  `file name` 
action\_result\.data\.\*\.process\.results\.\*\.process\_pid | numeric |  `pid` 
action\_result\.data\.\*\.process\.results\.\*\.processblock\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.regmod\_count | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.segment\_id | numeric | 
action\_result\.data\.\*\.process\.results\.\*\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.process\.results\.\*\.start | string | 
action\_result\.data\.\*\.process\.results\.\*\.terminated | boolean | 
action\_result\.data\.\*\.process\.results\.\*\.unique\_id | string | 
action\_result\.data\.\*\.process\.results\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.process\.start | numeric | 
action\_result\.data\.\*\.process\.terms | string | 
action\_result\.data\.\*\.process\.total\_results | numeric | 
action\_result\.summary\.device\_count | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create alert'
Create an alert/watchlist

Type: **generic**  
Read only: **False**

Carbon Black Response supports 'watchlists' which are customized alerts that search for a binary or running process on an endpoint that matches a certain query\. See the carbonblack\_app playbook for examples\.<br>This action requires only a Carbon Black Response <b>api\_token</b>\. The Carbon Black Response user assigned to that token does not require any privileges \(i\.e\. No Access\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name of created alert/watchlist | string |  `carbon black watchlist` 
**type** |  required  | Type of the query | string |  `carbon black query type` 
**query** |  required  | Query to add the watchlist for | string |  `carbon black query` 
**read\_only** |  optional  | Read\-only watchlist | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.name | string |  `carbon black watchlist` 
action\_result\.parameter\.query | string |  `carbon black query` 
action\_result\.parameter\.read\_only | boolean | 
action\_result\.parameter\.type | string |  `carbon black query type` 
action\_result\.data\.\*\.alliance\_id | string | 
action\_result\.data\.\*\.date\_added | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.enabled | boolean | 
action\_result\.data\.\*\.from\_alliance | boolean | 
action\_result\.data\.\*\.group\_id | numeric | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.index\_type | string | 
action\_result\.data\.\*\.last\_hit | string | 
action\_result\.data\.\*\.last\_hit\_count | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.query\_type | string |  `carbon black query type` 
action\_result\.data\.\*\.quoted\_query | string |  `carbon black query` 
action\_result\.data\.\*\.readonly | boolean | 
action\_result\.data\.\*\.search\_query | string |  `file name` 
action\_result\.data\.\*\.search\_timestamp | string | 
action\_result\.data\.\*\.total\_hits | string | 
action\_result\.data\.\*\.total\_tags | string | 
action\_result\.summary\.new\_watchlist\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update alerts'
Update or resolve an alert

Type: **generic**  
Read only: **False**

Allows for update of one or more alerts by alert id\(s\) or by query\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  optional  | Query to run \(Carbon Black Response search language\)\. Parameter accepts the same data as the alert search box on the Triage Alerts page | string |  `carbon black query` 
**alert\_ids** |  optional  | Unique ID of alert or comma\-separated list of unique alert IDs to update | string |  `carbon black alert id` 
**requested\_status** |  required  | New status of the alert\(s\) | string | 
**set\_ignored** |  optional  | If set to true, modifies threat report so that any further hits on IOCs contained within that report will no longer trigger an alert | boolean | 
**assigned\_to** |  optional  | Assign owner of alert | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary\.result | string | 
action\_result\.summary\.Total records updated | numeric | 
action\_result\.parameter\.query | string |  `carbon black query` 
action\_result\.parameter\.set\_ignored | numeric | 
action\_result\.parameter\.requested\_status | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.parameter\.alert\_ids | string |  `carbon black alert id` 
action\_result\.parameter\.assigned\_to | string | 
action\_result\.data\.\*\.result | string |   

## action: 'run query'
Run a search query on the device

Type: **investigate**  
Read only: **True**

This action requires only a Carbon Black Response <b>api\_token</b>\. The Carbon Black Response user assigned to that token does not require any privileges \(i\.e\. No Access\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  required  | Query to run \(Carbon Black Response search language\) | string |  `carbon black query` 
**type** |  required  | Type of search | string |  `carbon black query type` 
**range** |  optional  | Range of items to return, for e\.g\. 0\-10 | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.query | string |  `carbon black query` 
action\_result\.parameter\.range | string | 
action\_result\.parameter\.type | string |  `carbon black query type` 
action\_result\.data\.\*\.all\_segments | boolean | 
action\_result\.data\.\*\.comprehensive\_search | boolean | 
action\_result\.data\.\*\.elapsed | numeric | 
action\_result\.data\.\*\.facets\.alliance\_score\_virustotal\.\*\.name | numeric | 
action\_result\.data\.\*\.facets\.alliance\_score\_virustotal\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.company\_name\_facet\.\*\.name | string | 
action\_result\.data\.\*\.facets\.company\_name\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.company\_name\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.company\_name\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.day\_of\_week\.\*\.name | string | 
action\_result\.data\.\*\.facets\.day\_of\_week\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.digsig\_publisher\_facet\.\*\.name | string | 
action\_result\.data\.\*\.facets\.digsig\_publisher\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.digsig\_publisher\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.digsig\_publisher\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.digsig\_result\.\*\.name | string | 
action\_result\.data\.\*\.facets\.digsig\_result\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.digsig\_result\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.digsig\_result\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.digsig\_sign\_time\.\*\.name | string | 
action\_result\.data\.\*\.facets\.digsig\_sign\_time\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.file\_version\_facet\.\*\.name | string | 
action\_result\.data\.\*\.facets\.file\_version\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.file\_version\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.file\_version\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.group\.\*\.name | string | 
action\_result\.data\.\*\.facets\.group\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.group\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.group\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.host\_count\.\*\.name | string | 
action\_result\.data\.\*\.facets\.host\_count\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.host\_type\.\*\.name | string | 
action\_result\.data\.\*\.facets\.host\_type\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.host\_type\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.host\_type\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.hostname\.\*\.name | string |  `host name` 
action\_result\.data\.\*\.facets\.hostname\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.hostname\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.hostname\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.hour\_of\_day\.\*\.name | string | 
action\_result\.data\.\*\.facets\.hour\_of\_day\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.observed\_filename\_facet\.\*\.name | string |  `file path`  `file name` 
action\_result\.data\.\*\.facets\.observed\_filename\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.observed\_filename\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.observed\_filename\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.parent\_name\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.facets\.parent\_name\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.parent\_name\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.parent\_name\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.path\_full\.\*\.name | string |  `file path`  `file name` 
action\_result\.data\.\*\.facets\.path\_full\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.path\_full\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.path\_full\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.process\_md5\.\*\.name | string |  `md5` 
action\_result\.data\.\*\.facets\.process\_md5\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.process\_md5\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.process\_md5\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.process\_name\.\*\.name | string |  `file name` 
action\_result\.data\.\*\.facets\.process\_name\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.process\_name\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.process\_name\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.product\_name\_facet\.\*\.name | string | 
action\_result\.data\.\*\.facets\.product\_name\_facet\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.product\_name\_facet\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.product\_name\_facet\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.server\_added\_timestamp\.\*\.name | string | 
action\_result\.data\.\*\.facets\.server\_added\_timestamp\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.start\.\*\.name | string | 
action\_result\.data\.\*\.facets\.start\.\*\.value | numeric | 
action\_result\.data\.\*\.facets\.username\_full\.\*\.name | string | 
action\_result\.data\.\*\.facets\.username\_full\.\*\.percent | numeric | 
action\_result\.data\.\*\.facets\.username\_full\.\*\.ratio | string | 
action\_result\.data\.\*\.facets\.username\_full\.\*\.value | numeric | 
action\_result\.data\.\*\.highlights\.\*\.ids | string |  `md5` 
action\_result\.data\.\*\.highlights\.\*\.name | string |  `file path` 
action\_result\.data\.\*\.incomplete\_results | boolean | 
action\_result\.data\.\*\.results\.\*\.alliance\_data\_srstrust | string |  `md5` 
action\_result\.data\.\*\.results\.\*\.alliance\_link\_srstrust | string |  `url` 
action\_result\.data\.\*\.results\.\*\.alliance\_score\_srstrust | numeric | 
action\_result\.data\.\*\.results\.\*\.alliance\_updated\_srstrust | string | 
action\_result\.data\.\*\.results\.\*\.cb\_version | numeric | 
action\_result\.data\.\*\.results\.\*\.childproc\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.cmdline | string |  `file path` 
action\_result\.data\.\*\.results\.\*\.comments | string | 
action\_result\.data\.\*\.results\.\*\.comms\_ip | numeric | 
action\_result\.data\.\*\.results\.\*\.company\_name | string | 
action\_result\.data\.\*\.results\.\*\.copied\_mod\_len | numeric | 
action\_result\.data\.\*\.results\.\*\.crossproc\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.digsig\_issuer | string | 
action\_result\.data\.\*\.results\.\*\.digsig\_prog\_name | string |  `file name` 
action\_result\.data\.\*\.results\.\*\.digsig\_publisher | string | 
action\_result\.data\.\*\.results\.\*\.digsig\_result | string | 
action\_result\.data\.\*\.results\.\*\.digsig\_result\_code | string | 
action\_result\.data\.\*\.results\.\*\.digsig\_sign\_time | string | 
action\_result\.data\.\*\.results\.\*\.digsig\_subject | string | 
action\_result\.data\.\*\.results\.\*\.emet\_config | string | 
action\_result\.data\.\*\.results\.\*\.emet\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.endpoint | string | 
action\_result\.data\.\*\.results\.\*\.event\_partition\_id | numeric | 
action\_result\.data\.\*\.results\.\*\.facet\_id | numeric | 
action\_result\.data\.\*\.results\.\*\.file\_desc | string |  `file name` 
action\_result\.data\.\*\.results\.\*\.file\_version | string | 
action\_result\.data\.\*\.results\.\*\.filemod\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.filtering\_known\_dlls | boolean | 
action\_result\.data\.\*\.results\.\*\.group | string | 
action\_result\.data\.\*\.results\.\*\.host\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.host\_type | string | 
action\_result\.data\.\*\.results\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.results\.\*\.id | string | 
action\_result\.data\.\*\.results\.\*\.interface\_ip | numeric | 
action\_result\.data\.\*\.results\.\*\.internal\_name | string |  `file name` 
action\_result\.data\.\*\.results\.\*\.is\_64bit | boolean | 
action\_result\.data\.\*\.results\.\*\.is\_executable\_image | boolean | 
action\_result\.data\.\*\.results\.\*\.last\_seen | string | 
action\_result\.data\.\*\.results\.\*\.last\_server\_update | string | 
action\_result\.data\.\*\.results\.\*\.last\_update | string | 
action\_result\.data\.\*\.results\.\*\.legal\_copyright | string | 
action\_result\.data\.\*\.results\.\*\.md5 | string |  `md5` 
action\_result\.data\.\*\.results\.\*\.modload\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.netconn\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.observed\_filename | string |  `file name`  `file path` 
action\_result\.data\.\*\.results\.\*\.orig\_mod\_len | numeric | 
action\_result\.data\.\*\.results\.\*\.original\_filename | string |  `file name` 
action\_result\.data\.\*\.results\.\*\.os\_type | string | 
action\_result\.data\.\*\.results\.\*\.parent\_id | string | 
action\_result\.data\.\*\.results\.\*\.parent\_md5 | string |  `md5` 
action\_result\.data\.\*\.results\.\*\.parent\_name | string |  `file name` 
action\_result\.data\.\*\.results\.\*\.parent\_pid | numeric | 
action\_result\.data\.\*\.results\.\*\.parent\_unique\_id | string | 
action\_result\.data\.\*\.results\.\*\.path | string |  `file path`  `file name` 
action\_result\.data\.\*\.results\.\*\.private\_build | string | 
action\_result\.data\.\*\.results\.\*\.process\_md5 | string |  `md5` 
action\_result\.data\.\*\.results\.\*\.process\_name | string |  `process name`  `file name` 
action\_result\.data\.\*\.results\.\*\.process\_pid | numeric |  `pid` 
action\_result\.data\.\*\.results\.\*\.processblock\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.product\_name | string | 
action\_result\.data\.\*\.results\.\*\.product\_version | string | 
action\_result\.data\.\*\.results\.\*\.regmod\_count | numeric | 
action\_result\.data\.\*\.results\.\*\.segment\_id | numeric | 
action\_result\.data\.\*\.results\.\*\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.results\.\*\.server\_added\_timestamp | string | 
action\_result\.data\.\*\.results\.\*\.signed | string | 
action\_result\.data\.\*\.results\.\*\.start | string | 
action\_result\.data\.\*\.results\.\*\.terminated | boolean | 
action\_result\.data\.\*\.results\.\*\.timestamp | string | 
action\_result\.data\.\*\.results\.\*\.unique\_id | string | 
action\_result\.data\.\*\.results\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.results\.\*\.watchlists\.\*\.value | string | 
action\_result\.data\.\*\.results\.\*\.watchlists\.\*\.wid | string | 
action\_result\.data\.\*\.start | numeric | 
action\_result\.data\.\*\.terms | string |  `file name` 
action\_result\.data\.\*\.total\_results | numeric | 
action\_result\.summary\.number\_of\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list alerts'
List all the alerts/watchlists configured on the device

Type: **investigate**  
Read only: **True**

This action requires only a Carbon Black Response <b>api\_token</b>\. The Carbon Black Response user assigned to that token does not require any privileges \(i\.e\. No Access\)\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.alliance\_id | string | 
action\_result\.data\.\*\.date\_added | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.enabled | boolean | 
action\_result\.data\.\*\.from\_alliance | boolean | 
action\_result\.data\.\*\.group\_id | numeric | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.index\_type | string | 
action\_result\.data\.\*\.last\_hit | string | 
action\_result\.data\.\*\.last\_hit\_count | numeric | 
action\_result\.data\.\*\.name | string |  `ip` 
action\_result\.data\.\*\.query\_type | string |  `carbon black query type` 
action\_result\.data\.\*\.quoted\_query | string |  `carbon black query`  `file name` 
action\_result\.data\.\*\.readonly | boolean | 
action\_result\.data\.\*\.search\_query | string |  `file name` 
action\_result\.data\.\*\.search\_timestamp | string | 
action\_result\.data\.\*\.total\_hits | string | 
action\_result\.data\.\*\.total\_tags | string | 
action\_result\.summary\.total\_alerts | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

This action requires Carbon Black Response view privileges to list sensors and therefore a list of endpoints known to Carbon Black Response\. If this privilege is not assigned to the asset <b>api\_token</b>, the action will succeed and return an empty list\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.boot\_id | string | 
action\_result\.data\.\*\.build\_id | numeric | 
action\_result\.data\.\*\.build\_version\_string | string | 
action\_result\.data\.\*\.clock\_delta | string | 
action\_result\.data\.\*\.computer\_dns\_name | string | 
action\_result\.data\.\*\.computer\_name | string |  `host name` 
action\_result\.data\.\*\.computer\_sid | string | 
action\_result\.data\.\*\.cookie | numeric | 
action\_result\.data\.\*\.display | boolean | 
action\_result\.data\.\*\.emet\_dump\_flags | string | 
action\_result\.data\.\*\.emet\_exploit\_action | string | 
action\_result\.data\.\*\.emet\_is\_gpo | boolean | 
action\_result\.data\.\*\.emet\_process\_count | numeric | 
action\_result\.data\.\*\.emet\_report\_setting | string | 
action\_result\.data\.\*\.emet\_telemetry\_path | string | 
action\_result\.data\.\*\.emet\_version | string | 
action\_result\.data\.\*\.event\_log\_flush\_time | string | 
action\_result\.data\.\*\.group\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.ips | string |  `ip` 
action\_result\.data\.\*\.is\_isolating | boolean | 
action\_result\.data\.\*\.last\_checkin\_time | string | 
action\_result\.data\.\*\.last\_update | string | 
action\_result\.data\.\*\.license\_expiration | string | 
action\_result\.data\.\*\.network\_adapters | string | 
action\_result\.data\.\*\.network\_isolation\_enabled | boolean | 
action\_result\.data\.\*\.next\_checkin\_time | string | 
action\_result\.data\.\*\.node\_id | numeric | 
action\_result\.data\.\*\.notes | string | 
action\_result\.data\.\*\.num\_eventlog\_bytes | string | 
action\_result\.data\.\*\.num\_storefiles\_bytes | string | 
action\_result\.data\.\*\.os\_environment\_display\_string | string | 
action\_result\.data\.\*\.os\_environment\_id | numeric | 
action\_result\.data\.\*\.os\_type | numeric | 
action\_result\.data\.\*\.parity\_host\_id | string | 
action\_result\.data\.\*\.physical\_memory\_size | string | 
action\_result\.data\.\*\.power\_state | string | 
action\_result\.data\.\*\.registration\_time | string | 
action\_result\.data\.\*\.restart\_queued | boolean | 
action\_result\.data\.\*\.sensor\_health\_message | string | 
action\_result\.data\.\*\.sensor\_health\_status | numeric | 
action\_result\.data\.\*\.sensor\_uptime | string | 
action\_result\.data\.\*\.shard\_id | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.supports\_2nd\_gen\_modloads | boolean | 
action\_result\.data\.\*\.supports\_cblr | boolean | 
action\_result\.data\.\*\.supports\_isolation | boolean | 
action\_result\.data\.\*\.systemvolume\_free\_size | string | 
action\_result\.data\.\*\.systemvolume\_total\_size | string | 
action\_result\.data\.\*\.uninstall | boolean | 
action\_result\.data\.\*\.uninstalled | string | 
action\_result\.data\.\*\.uptime | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine device'
Quarantine the endpoint

Type: **contain**  
Read only: **False**

Carbon Black Response can have multiple entries that match an ip address, even a hostname\. This could happen if a machine was removed and re\-added to Carbon Black Response after an extended period\. Carbon Black Response also supports partial matches for hostnames, e\.g\. if <b>ip\_hostname</b> is specified as <i>WIN</i> then this will match endpoints with hostname <i>WINXP</i> and <i>WIN8</i>\. The action will return an <b>error</b> if multiple <b>online</b> endpoints match the input parameter\.<br>This action requires administrative privileges to search for the given endpoints and set the quarantine/isolation state\. If this privilege is not assigned to the asset <b>api\_token</b>, the action may return an empty list or <b>HTTP 405 Method Not Allowed</b> error\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of endpoint to quarantine | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Unquarantine the endpoint

Type: **correct**  
Read only: **False**

Carbon Black Response can have multiple entries that match an ip address, even a hostname\. This could happen if a machine was removed and re\-added to Carbon Black Response after an extended period\. Carbon Black Response also supports partial matches for hostnames, e\.g\. if <b>ip\_hostname</b> is specified as <i>WIN</i> then this will match endpoints with hostname <i>WINXP</i> and <i>WIN8</i>\. The action will return an <b>error</b> if multiple <b>online</b> endpoints match the input parameter\.<br>This action requires administrative privileges to search for the given endpoints and re\-set the quarantine/isolation state\. If this privilege is not assigned to the asset <b>api\_token</b>, the action may return an empty list or <b>HTTP 405 Method Not Allowed</b> error\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  required  | Hostname/IP of endpoint to unquarantine | string |  `host name`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'sync events'
Force a sensor to sync all queued events to the server

Type: **generic**  
Read only: **False**

Force the specified sensor to synchronize all queued events that have been observed on the endpoint but have not yet been uploaded to the server and made searchable\. This may generate a significant amount of network traffic because it overrides the default behavior that rate\-limits the RabbitMQ messages to conserve bandwidth\. As specified by the Carbon Black Response API, this flush is implemented by writing a future date to the sensor's <b>event\_log\_flush\_time</b>\. In this case, the current time plus one day is used because that is how it is done in the official Python API \(https\://github\.com/carbonblack/cbapi\-python\)\.<br>If <b>sensor\_id</b> is specified, <b>ip\_hostname</b> will be ignored\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | Hostname/IP address to sync events for | string |  `host name`  `ip` 
**sensor\_id** |  optional  | Carbon Black sensor id to sync events for | numeric |  `carbon black sensor id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Get information about an endpoint

Type: **investigate**  
Read only: **True**

This action requires Carbon Black Response view privileges to list sensors and therefore a list of endpoints known to Carbon Black Response\. If this privilege is not assigned to the asset <b>api\_token</b>, the action will succeed and return an empty list\.<br>If <b>sensor\_id</b> is specified, other input parameters will be ignored\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | Hostname/IP address to get info of | string |  `host name`  `ip` 
**sensor\_id** |  optional  | Carbon Black sensor id | numeric |  `carbon black sensor id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `host name`  `ip` 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.boot\_id | string | 
action\_result\.data\.\*\.build\_id | numeric | 
action\_result\.data\.\*\.build\_version\_string | string | 
action\_result\.data\.\*\.clock\_delta | string | 
action\_result\.data\.\*\.computer\_dns\_name | string | 
action\_result\.data\.\*\.computer\_name | string |  `host name` 
action\_result\.data\.\*\.computer\_sid | string | 
action\_result\.data\.\*\.cookie | numeric | 
action\_result\.data\.\*\.display | boolean | 
action\_result\.data\.\*\.emet\_dump\_flags | string | 
action\_result\.data\.\*\.emet\_exploit\_action | string | 
action\_result\.data\.\*\.emet\_is\_gpo | boolean | 
action\_result\.data\.\*\.emet\_process\_count | numeric | 
action\_result\.data\.\*\.emet\_report\_setting | string | 
action\_result\.data\.\*\.emet\_telemetry\_path | string | 
action\_result\.data\.\*\.emet\_version | string | 
action\_result\.data\.\*\.event\_log\_flush\_time | string | 
action\_result\.data\.\*\.group\_id | numeric | 
action\_result\.data\.\*\.id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.ips | string |  `ip` 
action\_result\.data\.\*\.is\_isolating | boolean | 
action\_result\.data\.\*\.last\_checkin\_time | string | 
action\_result\.data\.\*\.last\_update | string | 
action\_result\.data\.\*\.license\_expiration | string | 
action\_result\.data\.\*\.network\_adapters | string | 
action\_result\.data\.\*\.network\_isolation\_enabled | boolean | 
action\_result\.data\.\*\.next\_checkin\_time | string | 
action\_result\.data\.\*\.node\_id | numeric | 
action\_result\.data\.\*\.notes | string | 
action\_result\.data\.\*\.num\_eventlog\_bytes | string | 
action\_result\.data\.\*\.num\_storefiles\_bytes | string | 
action\_result\.data\.\*\.os\_environment\_display\_string | string | 
action\_result\.data\.\*\.os\_environment\_id | numeric | 
action\_result\.data\.\*\.os\_type | numeric | 
action\_result\.data\.\*\.parity\_host\_id | string | 
action\_result\.data\.\*\.physical\_memory\_size | string | 
action\_result\.data\.\*\.power\_state | numeric | 
action\_result\.data\.\*\.registration\_time | string | 
action\_result\.data\.\*\.restart\_queued | boolean | 
action\_result\.data\.\*\.sensor\_health\_message | string | 
action\_result\.data\.\*\.sensor\_health\_status | numeric | 
action\_result\.data\.\*\.sensor\_uptime | string | 
action\_result\.data\.\*\.shard\_id | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.supports\_2nd\_gen\_modloads | boolean | 
action\_result\.data\.\*\.supports\_cblr | boolean | 
action\_result\.data\.\*\.supports\_isolation | boolean | 
action\_result\.data\.\*\.systemvolume\_free\_size | string | 
action\_result\.data\.\*\.systemvolume\_total\_size | string | 
action\_result\.data\.\*\.uninstall | boolean | 
action\_result\.data\.\*\.uninstalled | string | 
action\_result\.data\.\*\.uptime | string | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list processes'
List the running processes on a machine

Type: **investigate**  
Read only: **True**

If <b>sensor\_id</b> is specified, other input parameters will be ignored \(and removed from the resultant <i>parameter</i> dictionary\), else the App searches for endpoints that match the value specified in <b>ip\_hostname</b>\. Carbon Black Response can have multiple entries that match an ip address, even a hostname\. This could happen if a machine was removed and re\-added to Carbon Black Response after an extended period\. Carbon Black Response also supports partial matches for hostnames, for e\.g\. if <b>ip\_hostname</b> is specified as <i>WIN</i> then this will match endpoints with hostname <i>WINXP</i> and <i>WIN8</i> and in this case, the action will try to get the <i>process list</i> for all the matching endpoints\.<br>This action requires Carbon Black Response administrative privileges\. If this privilege is not assigned to the asset <b>api\_token</b>, the action may return an empty list or <b>HTTP 405 Method Not Allowed</b> error\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | Name/IP of the machine to list processes on | string |  `ip`  `host name` 
**sensor\_id** |  optional  | Carbon Black sensor id | numeric |  `carbon black sensor id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.command\_line | string |  `file name`  `file path` 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.name | string |  `process name`  `file name` 
action\_result\.data\.\*\.parent | numeric |  `pid` 
action\_result\.data\.\*\.parent\_guid | string | 
action\_result\.data\.\*\.path | string |  `file name`  `file path` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.proc\_guid | string | 
action\_result\.data\.\*\.sid | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary\.total\_processes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'terminate process'
Kill running processes on a machine

Type: **contain**  
Read only: **False**

If <b>sensor\_id</b> is specified, other input parameters will be ignored \(and removed from the resultant <i>parameter</i> dictionary\), else the App searches for endpoints that match the value specified in <b>ip\_hostname</b>\. Carbon Black Response can have multiple entries that match an ip address, even a hostname\. This could happen if a machine was removed and re\-added to Carbon Black Response after an extended period of time\. Carbon Black Response also supports partial matches for hostnames, for e\.g\. if <b>ip\_hostname</b> is specified as <i>WIN</i> then this will match endpoints with hostname <i>WINXP</i> and <i>WIN8</i>\. If the input hostname matches more than one ONLINE endpoint the action will treat this as an error\.<br>This action requires Carbon Black Response administrative privileges\. If this privilege is not assigned to the asset <b>api\_token</b>, the action may return an empty list or <b>HTTP 405 Method Not Allowed</b> error\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | Name/IP of the machine to terminate process on | string |  `ip`  `host name` 
**sensor\_id** |  optional  | Carbon Black sensor id | numeric |  `carbon black sensor id` 
**pid** |  required  | PID of process to terminate | numeric |  `pid` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.pid | numeric |  `pid` 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.completion | numeric | 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.object | numeric | 
action\_result\.data\.\*\.result\_code | numeric | 
action\_result\.data\.\*\.result\_desc | string | 
action\_result\.data\.\*\.result\_type | string | 
action\_result\.data\.\*\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.session\_id | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file'
Download a file from Carbon Black Response and add it to the vault

Type: **investigate**  
Read only: **True**

To get a file from a source, provide a sensor\_id, file\_source, optional offset, and optional get\_count\. Otherwise, provide a hash, which also tries to get file information from the Carbon Black Response server if available\. If the hash is provided, all the other input parameters will be ignored\.<br>A file that shows up in the results of the <b>hunt file</b> action might still not be available for download in case the endpoint sensor is not connected to the server\. This action requires only a Carbon Black Response <b>api\_token</b>\. The Carbon Black Response user assigned to that token does not require any privileges \(i\.e\. No Access\)\.<br>Note\: For Carbon Black Response version 7\.x, the 'get file' action sometimes fails for valid hashes\. The action replicates the API result\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  optional  | MD5 of file/sample to download | string |  `md5`  `hash` 
**sensor\_id** |  optional  | Carbon Black sensor id to sync events for\. Required for getting file from source | numeric |  `carbon black sensor id` 
**file\_source** |  optional  | Source path of the file | string |  `file path` 
**offset** |  optional  | When source is defined, set the byte offset to start getting the file\. Supports a partial get\. Optional for getting file from source | numeric | 
**get\_count** |  optional  | When source is defined, set the number of bytes to grab\. Optional for getting file from source | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.file\_source | string |  `file path` 
action\_result\.parameter\.get\_count | numeric | 
action\_result\.parameter\.hash | string |  `md5`  `hash` 
action\_result\.parameter\.offset | numeric | 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.file\_details\.alliance\_data\_srstrust | string |  `md5` 
action\_result\.data\.\*\.file\_details\.alliance\_link\_srstrust | string |  `url` 
action\_result\.data\.\*\.file\_details\.alliance\_score\_srstrust | numeric | 
action\_result\.data\.\*\.file\_details\.alliance\_updated\_srstrust | string | 
action\_result\.data\.\*\.file\_details\.cb\_version | numeric | 
action\_result\.data\.\*\.file\_details\.company\_name | string | 
action\_result\.data\.\*\.file\_details\.copied\_mod\_len | numeric | 
action\_result\.data\.\*\.file\_details\.digsig\_publisher | string | 
action\_result\.data\.\*\.file\_details\.digsig\_result | string | 
action\_result\.data\.\*\.file\_details\.digsig\_result\_code | string | 
action\_result\.data\.\*\.file\_details\.digsig\_sign\_time | string | 
action\_result\.data\.\*\.file\_details\.endpoint | string | 
action\_result\.data\.\*\.file\_details\.event\_partition\_id | numeric | 
action\_result\.data\.\*\.file\_details\.facet\_id | numeric | 
action\_result\.data\.\*\.file\_details\.file\_desc | string | 
action\_result\.data\.\*\.file\_details\.file\_version | string | 
action\_result\.data\.\*\.file\_details\.group | string | 
action\_result\.data\.\*\.file\_details\.host\_count | numeric | 
action\_result\.data\.\*\.file\_details\.icon | string | 
action\_result\.data\.\*\.file\_details\.internal\_name | string |  `file name` 
action\_result\.data\.\*\.file\_details\.is\_64bit | boolean | 
action\_result\.data\.\*\.file\_details\.is\_executable\_image | boolean | 
action\_result\.data\.\*\.file\_details\.last\_seen | string | 
action\_result\.data\.\*\.file\_details\.legal\_copyright | string | 
action\_result\.data\.\*\.file\_details\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.file\_details\.observed\_filename | string |  `file path`  `file name` 
action\_result\.data\.\*\.file\_details\.orig\_mod\_len | numeric | 
action\_result\.data\.\*\.file\_details\.original\_filename | string |  `file name` 
action\_result\.data\.\*\.file\_details\.os\_type | string | 
action\_result\.data\.\*\.file\_details\.product\_name | string | 
action\_result\.data\.\*\.file\_details\.product\_version | string | 
action\_result\.data\.\*\.file\_details\.server\_added\_timestamp | string | 
action\_result\.data\.\*\.file\_details\.signed | string | 
action\_result\.data\.\*\.file\_details\.timestamp | string | 
action\_result\.data\.\*\.file\_details\.watchlists\.\*\.value | string | 
action\_result\.data\.\*\.file\_details\.watchlists\.\*\.wid | string | 
action\_result\.data\.\*\.file\_id | numeric | 
action\_result\.data\.\*\.name | string |  `file name`  `file path` 
action\_result\.data\.\*\.session\_id | numeric | 
action\_result\.data\.\*\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.summary\.cb\_url | string |  `url` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string |  `file name`  `file path` 
action\_result\.summary\.vault\_id | string |  `vault id`  `sha1` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'put file'
Upload file to a Windows hostname

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | Vault id of file to upload | string |  `vault id` 
**destination** |  required  | Destination path of the file \(ie\: C\:\\Windows\\CarbonBlack\\MyFolder\\filename\) | string |  `file path` 
**sensor\_id** |  required  | Carbon Black sensor id to sync events for | numeric |  `carbon black sensor id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.destination | string |  `file path` 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data\.\*\.chunk\_num | numeric | 
action\_result\.data\.\*\.completion | numeric | 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.file\_id | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.object | string |  `file path` 
action\_result\.data\.\*\.result\_code | numeric | 
action\_result\.data\.\*\.result\_desc | string | 
action\_result\.data\.\*\.result\_type | string | 
action\_result\.data\.\*\.sensor\_id | numeric | 
action\_result\.data\.\*\.session\_id | numeric |  `carbon black session id` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'run command'
Issue a Carbon Black Response command by providing the command name and the command's parameters as the 'data'

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor\_id** |  required  | Carbon Black sensor id to sync events for | numeric |  `carbon black sensor id` 
**command** |  required  | Command to run | string | 
**data** |  required  | JSON formatted body\. Refer to Carbon Black REST API for command parameters | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.command | string | 
action\_result\.parameter\.data | string | 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.completion | numeric | 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.file\_id | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.object | string |  `file path`  `file name` 
action\_result\.data\.\*\.processes\.\*\.command\_line | string | 
action\_result\.data\.\*\.processes\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.processes\.\*\.parent | numeric | 
action\_result\.data\.\*\.processes\.\*\.parent\_guid | string | 
action\_result\.data\.\*\.processes\.\*\.path | string | 
action\_result\.data\.\*\.processes\.\*\.pid | numeric | 
action\_result\.data\.\*\.processes\.\*\.proc\_guid | string | 
action\_result\.data\.\*\.processes\.\*\.sid | string | 
action\_result\.data\.\*\.processes\.\*\.username | string | 
action\_result\.data\.\*\.result\_code | numeric | 
action\_result\.data\.\*\.result\_desc | string | 
action\_result\.data\.\*\.result\_type | string | 
action\_result\.data\.\*\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.session\_id | numeric |  `carbon black session id` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'execute program'
Execute a process

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor\_id** |  required  | Carbon Black sensor id to sync events for | numeric |  `carbon black sensor id` 
**entire\_executable\_path** |  required  | Path and command line of the executable | string |  `file path`  `file name` 
**output\_file** |  optional  | File that STDERR and STDOUT will be redirected to | string | 
**working\_directory** |  optional  | The working directory of the executable | string | 
**wait** |  optional  | Wait for the process to complete execution before reporting the result | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.entire\_executable\_path | string |  `file path`  `file name` 
action\_result\.parameter\.output\_file | string | 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.parameter\.wait | boolean | 
action\_result\.parameter\.working\_directory | string | 
action\_result\.data\.\*\.completion | numeric | 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.object | string |  `file path`  `file name` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.result\_code | numeric | 
action\_result\.data\.\*\.result\_desc | string | 
action\_result\.data\.\*\.result\_type | string | 
action\_result\.data\.\*\.return\_code | numeric | 
action\_result\.data\.\*\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.session\_id | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.wait | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'memory dump'
Memory dump for a specified path

Type: **generic**  
Read only: **False**

This action will work for the windows endpoint\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**sensor\_id** |  required  | Carbon Black sensor id to sync events for | numeric |  `carbon black sensor id` 
**destination\_path** |  required  | Path on endpoint to save the resulting memory dump \(ie\: C\:\\Windows\\CarbonBlack\\Folder\) | string |  `file path` 
**compress** |  optional  | Compress the memory dump | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.compress | boolean | 
action\_result\.parameter\.destination\_path | string |  `file path` 
action\_result\.parameter\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.complete | boolean | 
action\_result\.data\.\*\.completion | numeric | 
action\_result\.data\.\*\.compressing | boolean | 
action\_result\.data\.\*\.create\_time | numeric | 
action\_result\.data\.\*\.dumping | boolean | 
action\_result\.data\.\*\.id | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.object | string |  `file path` 
action\_result\.data\.\*\.percentdone | numeric | 
action\_result\.data\.\*\.result\_code | numeric | 
action\_result\.data\.\*\.result\_desc | string | 
action\_result\.data\.\*\.result\_type | string | 
action\_result\.data\.\*\.return\_code | numeric | 
action\_result\.data\.\*\.sensor\_id | numeric |  `carbon black sensor id` 
action\_result\.data\.\*\.session\_id | numeric | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'reset session'
Tell the server to reset the sensor "sensor\_wait\_timeout"

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**session\_id** |  required  | Carbon Black session id | numeric |  `carbon black session id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.session\_id | numeric |  `carbon black session id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get file info'
Get info about a file from Carbon Black Response

Type: **investigate**  
Read only: **True**

This action requires only a Carbon Black Response <b>api\_token</b>\. The Carbon Black Response user assigned to that token does not require any privileges \(i\.e\. No Access\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | MD5 of file/sample to get info of | string |  `md5`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `md5`  `hash` 
action\_result\.data\.\*\.file\_details\.alliance\_data\_srstrust | string |  `md5` 
action\_result\.data\.\*\.file\_details\.alliance\_link\_srstrust | string |  `url` 
action\_result\.data\.\*\.file\_details\.alliance\_score\_srstrust | numeric | 
action\_result\.data\.\*\.file\_details\.alliance\_updated\_srstrust | string | 
action\_result\.data\.\*\.file\_details\.cb\_version | numeric | 
action\_result\.data\.\*\.file\_details\.company\_name | string | 
action\_result\.data\.\*\.file\_details\.copied\_mod\_len | numeric | 
action\_result\.data\.\*\.file\_details\.digsig\_issuer | string | 
action\_result\.data\.\*\.file\_details\.digsig\_prog\_name | string | 
action\_result\.data\.\*\.file\_details\.digsig\_publisher | string | 
action\_result\.data\.\*\.file\_details\.digsig\_result | string | 
action\_result\.data\.\*\.file\_details\.digsig\_result\_code | string | 
action\_result\.data\.\*\.file\_details\.digsig\_sign\_time | string | 
action\_result\.data\.\*\.file\_details\.digsig\_subject | string | 
action\_result\.data\.\*\.file\_details\.endpoint | string | 
action\_result\.data\.\*\.file\_details\.event\_partition\_id | numeric | 
action\_result\.data\.\*\.file\_details\.facet\_id | numeric | 
action\_result\.data\.\*\.file\_details\.file\_desc | string | 
action\_result\.data\.\*\.file\_details\.file\_version | string | 
action\_result\.data\.\*\.file\_details\.group | string | 
action\_result\.data\.\*\.file\_details\.host\_count | numeric | 
action\_result\.data\.\*\.file\_details\.icon | string | 
action\_result\.data\.\*\.file\_details\.internal\_name | string |  `file name` 
action\_result\.data\.\*\.file\_details\.is\_64bit | boolean | 
action\_result\.data\.\*\.file\_details\.is\_executable\_image | boolean | 
action\_result\.data\.\*\.file\_details\.last\_seen | string | 
action\_result\.data\.\*\.file\_details\.legal\_copyright | string | 
action\_result\.data\.\*\.file\_details\.md5 | string |  `md5`  `hash` 
action\_result\.data\.\*\.file\_details\.observed\_filename | string |  `file path`  `file name` 
action\_result\.data\.\*\.file\_details\.orig\_mod\_len | numeric | 
action\_result\.data\.\*\.file\_details\.original\_filename | string |  `file name` 
action\_result\.data\.\*\.file\_details\.os\_type | string | 
action\_result\.data\.\*\.file\_details\.product\_name | string | 
action\_result\.data\.\*\.file\_details\.product\_version | string | 
action\_result\.data\.\*\.file\_details\.server\_added\_timestamp | string | 
action\_result\.data\.\*\.file\_details\.signed | string | 
action\_result\.data\.\*\.file\_details\.timestamp | string | 
action\_result\.data\.\*\.file\_details\.watchlists\.\*\.value | string | 
action\_result\.data\.\*\.file\_details\.watchlists\.\*\.wid | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.vault\_id | string |  `vault id` 
action\_result\.summary\.architecture | string | 
action\_result\.summary\.cb\_url | string |  `url` 
action\_result\.summary\.file\_type | string | 
action\_result\.summary\.name | string |  `file name` 
action\_result\.summary\.os\_type | string | 
action\_result\.summary\.size | numeric | 
action\_result\.summary\.vault\_id | string |  `vault id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block hash'
Add a hash to the Carbon Black Response blacklist

Type: **contain**  
Read only: **False**

This action requires Carbon Black Response administrative privileges\. If this privilege is not assigned to the asset <b>api\_token</b>, the action may return an empty list or <b>HTTP 405 Method Not Allowed</b> error\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | MD5 of file to ban/block | string |  `md5`  `hash` 
**comment** |  optional  | Comment | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.comment | string | 
action\_result\.parameter\.hash | string |  `md5`  `hash` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock hash'
Unblock the hash

Type: **correct**  
Read only: **False**

This action requires Carbon Black Response administrative privileges\. If this privilege is not assigned to the asset <b>api\_token</b>, the action may return an empty list or <b>HTTP 405 Method Not Allowed</b> error\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hash** |  required  | MD5 of file to block | string |  `md5`  `hash` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hash | string |  `md5`  `hash` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list connections'
List all of the connections from a given process name, PID, or Carbon Black process ID

Type: **investigate**  
Read only: **True**

If either a process name or PID is provided, then a hostname must be provided as well\. If a PID is provided, the process name parameter will be ignored\. If a Carbon Black process ID is given, all of the other parameters will be ignored\. The Carbon Black process ID refers to the internal ID which Carbon Black Response assigns to every process\. It can be found in the action result of the hunt file in <b>action\_result\.data\.\*\.process\.results\.\*\.id</b> or in the output of this action\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_hostname** |  optional  | Hostname or IP | string |  `ip`  `host name` 
**process\_name** |  optional  | Name of process | string |  `process name` 
**pid** |  optional  | PID of process | numeric |  `pid` 
**carbonblack\_process\_id** |  optional  | Internal Carbon Black ID of process | string |  `carbon black process id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.carbonblack\_process\_id | string |  `carbon black process id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.pid | numeric |  `pid` 
action\_result\.parameter\.process\_name | string |  `process name` 
action\_result\.data\.\*\.carbonblack\_process\_id | string |  `carbon black process id` 
action\_result\.data\.\*\.direction | string | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.event\_time | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.ip\_addr | string |  `ip` 
action\_result\.data\.\*\.pid | numeric |  `pid` 
action\_result\.data\.\*\.port | string |  `port` 
action\_result\.data\.\*\.process\_name | string |  `process name` 
action\_result\.data\.\*\.protocol | string | 
action\_result\.summary\.total\_connections | numeric | 
action\_result\.summary\.total\_processes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'on poll'
Ingests unresolved alerts into Phantom

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start\_time** |  optional  | Start of the time range, in epoch time \(milliseconds\)\. If not specified, the default is the past\_days setting of the App | numeric | 
**end\_time** |  optional  | End of the time range, in epoch time \(milliseconds\)\. If not specified, the default is now | numeric | 
**container\_count** |  optional  | Maximum number of container records to query for | numeric | 
**artifact\_count** |  optional  | Maximum number of artifact records to query for | numeric | 

#### Action Output
No Output  

## action: 'get license'
Gets the license information of the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.actual\_sensor\_count | numeric | 
action\_result\.data\.\*\.license\_end\_date | string | 
action\_result\.data\.\*\.license\_expired | boolean | 
action\_result\.data\.\*\.license\_request\_block | string | 
action\_result\.data\.\*\.license\_valid | boolean | 
action\_result\.data\.\*\.licensed\_sensor\_count | numeric | 
action\_result\.data\.\*\.licensed\_sensor\_count\_exceeded | boolean | 
action\_result\.data\.\*\.server\_token | string | 
action\_result\.summary\.license\_valid | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
