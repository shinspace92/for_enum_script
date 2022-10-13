This will be a python script that will perform basic enumeration on a windows machine to aid forensics.

To dos:
1. Go through common registries and parse out the details into a nice format.
    a. Computer HW details
    b. Users
        i. Any newly created users?
        ii. Existing users?
        iii. Admin users?
        iv. Suspicious users?
    c. Programs
        i. UserAssist
        ii. RecentDocs
        iii. ShellBags
    d. Executions
        i. BAM
        ii. Shimcache
        iii. prefetch
    e. Persistence
        i. currentversion run/runonce keys
        ii. startup folders
        iii. services
2. Go through Windows Event Logs and parse out the details
    a. Common Event Ids for:
        i. Windows defender
        ii. services
        iii. Account logons
            1. Kerberos
        iv. powershell engine state
        v. batch script executions?
3. Go through Sysmon Logs and parse out details
    a. Common event ids

Foreseen Challenges:
    1. Accessing reg / event log / sysmon log values and trimming out unnecessary details
    2. Determining which are actually relevant data
    3. Portability without having to install so many custom libraries using pip
    4. Figure out how to interact with the SAM and parse out user account info
