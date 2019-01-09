# IDS Alerts Injection: McAfee NSM to Graylog
Converts raw McAfee IDS alerts to Common event Format (CEF) compliant messages and finally injects into Graylog.

### Use Case
Consider you have an infrastructure to push IDS alerts from McAfee NSM to Graylog to perform security analytics/correlation. Now, due to some reason McAfee IDS alerts did not make its way to Graylog. In scenarios like these, this script will come in handy. You can use the outcomes of this script to inject missing alerts to Graylog (If you are parsing logs in CEF format). 

### Prerequisites
1. Please go through the complete document (McAfee NSM- Manual Injection.docx) before you run this script
2. Install *xlrd*, *itertools* (Python v2 only) library/module using pip
3. Enter appropriate values in the **configuration** section of the code

### Usage
```
python NSMRawtoCEF.py
```
Output will be in *cef.txt* file (same directory) 

### Note
1. This script is written in v2.7.14
2. This script runs on both python v2.x.x and v3.x.x
3. Tested on McAfee NSM v8.3.7