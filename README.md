This will be a python script that will perform basic enumeration on a windows machine to aid forensics.

To Dos:
1. Go through common registries and parse out the details into a nice format.
    
Computer HW details - &check;
    
Users - Accessing SAM is quite tricky...

        Any newly created users?
        Existing users?
        Admin users?
        Suspicious users?

Programs & Execution (UserActivity) - Functionality &check;

    1. Code must be implemeneted further such that the function accepts user inputs for search time parameters, as well as a specific User SID.

    2. Instead of redirecting outputs of all the functions to one file, find a better organization of output of csv or tsv files grouped by different functions.

        UserAssist
        RecentDocs
        ShellBags - Tricky!
        App Compat Cache
        muicache
        bam
        prefetch

Persistence 

        currentversion run/runonce keys
        startup folders
        services

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
