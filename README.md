### Part 1: Load the Sample Dataset (provided)

The initial dataframe provided (df_silver) contains Sysmon logs.

### Part 2: Detection Engineering

df_silver dataframe shows sysmon logs from a Windows device. In order to test the hypothesis, the dataframe was filtered for DNS query events. As threat actors utilising Microsoft Office applications are to be targeted by the detection, the dataframe is filtered for "Microsoft Office" string anywhere in Image (the path of the executable that triggered the event), ending with ".exe". MS Office applications often query Microsoft, shown in legitimate query events in the logs, therefore, the next filter filters out legitmate DNS queries ending in "office.net" or "office.com". 

df_detect dataframe was created with the results, including _time, Computer, EventCode, User, Image, UserID, QueryName and QueryResults columns, relevant for a security analyst.

df_detect shows a single event detected by the logic, a DNS query initiated by WINWORD.EXE to www.mediafire.com, which is a filehosting site. This potentially indicates a macro running in MS Word, and pulling down a malicious file hosted on Mediafire. The queries resolve to Pv4 addresses owned by Cloudflare infrastructure, indicating that traffic to Mediafire is first routed to/proxied by Cloudflare.

### Part 3: Additional Steps

#### 3.1 Data Normalization

Splunk CIM Network Resolution (DNS) data model was utilised for normalisation of the output, chosen for its suitability for the type of event logs in df_detect.

#### 3.2 Write the result to a fictitious `alert` table

Information necessary for rapid triage and investigation was added as part of the output to the alert table (df_alert_table) including log source, alert title severity. MITRE ATT&CK Tactic and Technique were added for TTP mapping of alerts. Other columns were renamed for clarity.

#### 3.3 Threat Intel Enrichment on Domain in Query

I was unable to perform enrichment directly in this environment. In a real world scenario, one would be to perform a JOIN on a threat intel IOC table, if such a table were available in the SIEM. Alternatively, python could be utilised to perform API calls to threat intel sites to check the legitimacy of domains and resolved IPs, further enriching the alert table.

#### AI Utilised in Cyber Quest

AI was used to assist with setting up environment and troubleshooting issues with version control. It was also used to troubleshoot syntactical errors with code. It was not used for analysis of logs or for development of detection logic.