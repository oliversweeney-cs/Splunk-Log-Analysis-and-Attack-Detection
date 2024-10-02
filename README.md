# Splunk Data Analysis and Attack Detection

## Objective

The Splunk project was designed to demonstrate the ability to ingest, analyze, and detect cyber threats within a simulated environment using Splunk Enterprise. The goal was to monitor network activity logs, identify attack patterns, and gain insights into offensive and defensive security techniques. This project provided hands-on experience in detecting security threats and formulating appropriate responses.

## Skills Learned

- In-depth understanding of SIEM (Splunk) and its practical application in detecting security incidents.
- Proficiency in log ingestion, searching, and analysis within Splunk.
- Recognition of attack signatures, such as brute-force attempts and privilege escalations.
- Enhanced skills in identifying anomalies in network data and suspicious user activities.
- Ability to develop response strategies based on data analysis and threat detection.

## Tools Used

- Splunk Enterprise: Log ingestion, data searching, and analysis.
    
## Steps

### Step 1: Splunk Installation and Setup

In this phase, Splunk Enterprise was installed and configured on a virtual machine. I set up a Power user role to enable elevated permissions for data management and log analysis.

### Step 2: Ingesting Data into Splunk

I downloaded a 30-day Linux log dataset and ingested it into Splunk for analysis. This dataset contained logs of SSH login attempts and related network activities.

### Step 3: Analyzing Failed Login Attempts

By querying Splunk, I identified over 290,000 failed login attempts within the dataset, indicating a persistent brute-force attack. Many attempts targeted invalid users, suggesting the use of a dictionary attack.

Search Query:

_index=* source="linux_s_30DAY.log" "Failed password" | stats count by host_

Ref 3: Screenshot of failed login attempts statistics

![image](https://github.com/user-attachments/assets/ddcefefc-f587-443e-aaae-a229acdcf77a)


### **Step 4: Identifying Attack Sources**

Further analysis revealed multiple IP addresses involved in the attack, with specific addresses generating thousands of failed login attempts. These IPs are likely responsible for the brute-force attempts. I also wanted to identify the different ports targeted by the attack so we could identify the services under attack.

Ref 4: Screenshot of IP address distribution:

![image](https://github.com/user-attachments/assets/1b75a74b-118f-4ccc-be22-170f7063396e)

Ports attacked:

![image](https://github.com/user-attachments/assets/424e2001-377a-40ea-ac9e-6c719cc7895a)

Distribution of the number of attacks over the 30 days. 

![image](https://github.com/user-attachments/assets/596de024-53c0-46d2-b536-51a04b7295d5)


### **Step 5: Analysis of the data and further investigation.**

A thorough analysis of Linux_S_30DAY.log has been conducted using Splunk. The analysis revealed a significant number of failed login attempts, suggesting a potential brute force or dictionary attack. Further investigation into specific login activities identified a series of successful logins and subsequent commands executed under root privileges, which raise security concerns.

#### Total Failed Login Attempts:
*"index=* *source="linux_s_30DAY.log" "Failed password" | stats count by host"*

The search returned 300,000 failed login attempts across the period analysed (08/03/2024 to 09/02/2024). The high volume of failed login attempts indicates a persistent and aggressive effort to gain unauthorised access.

#### Invalid User Attempts:
_"index=* source="linux_s_30DAY.log" "Failed password for invalid user" | stats count"_

There were 125,188 attempts specifically targeting invalid users. This suggests that the attackers are using a dictionary attack approach, trying common usernames in hopes that one might exist on the system.

#### Top Source IP Addresses:
*index=* *source="linux_s_30DAY.log" "Failed password" | rex field=_raw "from\s<(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" | stats count by src_ip"*

The analysis identified multiple IP addresses involved in the attack, with the top IP addresses showing:
•	87.194.216.51: 9,342 attempts
•	211.166.11.101: 5,952 attempts
•	194.215.205.19: 4,644 attempts
These IP addresses are likely sources of the brute force attack and should be investigated or blocked, but as the results show, many different IP addresses were utilised. 

#### Login Attempts Over Time:
*"index=* *source="linux_s_30DAY.log" "Failed password" | timechart span=1d count by host"*

The time chart shows a consistent pattern of failed login attempts daily over a period of a month, with peaks occurring on specific days such as 08/11/2024 and 08/15/2024. This sustained activity suggests an ongoing automated attack.

#### Successful Logins Following Failed Attempts:
*"index=* *source= "linux_s_30DAY.log" ("Failed password" OR "Accepted password") | rex field=_raw "from\s<(?<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*user=(?<user>\w+)" | transaction src_ip user startswith= "Failed password" endswith=" Accepted password" maxspan=10s | search src_ip=* user=*"*

The search identified instances where a successful login followed a failed password attempt within a short time frame. This could indicate that the attackers eventually succeeded in guessing the correct password.

#### Suspicious Activity Post-Login:
Analysis of users via the interesting field "PWD" (Present Working Directory) revealed that djohnson, nsharpe, and myuan have a high number of failed password attempts throughout the month. After successfully logging in, these users immediately escalated privileges to root, which is highly suspicious and indicative of potential persistence mechanisms being set up.

#### Targeted Ports:
*"index=* *source="linux_s_30DAY.log" "Failed password" | rex field=_raw "port\s(?<port>\d+)" | stats count by port"*

Most attacks were targeted at the standard SSH port (22), with 148,532 attempts. However, there were also attempts on non-standard ports such as 4439, 4663, and 1833, indicating that the attackers were also probing for SSH services running on unusual ports.

#### Conclusion and Recommendations

The evidence strongly suggests that the server is under a sustained brute-force attack, with numerous IP addresses repeatedly attempting to guess valid usernames and passwords. The presence of successful logins following failed attempts, particularly involving the djohnson, nsharpe, and myuan accounts, raises serious concerns about potential system compromise and unauthorised root access. The consistent behaviour of immediate privilege escalation post-login across multiple users suggests that attackers may establish persistence mechanisms. The recommended actions are as follows:
- Blocking the offending IP addresses.
- Isolate and investigate the compromised user accounts further.
- Implementing more robust password policies and multi-factor authentication.

