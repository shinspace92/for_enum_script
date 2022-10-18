import os
from itertools import count
from io import BytesIO
from codecs import encode
from struct import unpack
from datetime import datetime, timedelta
from contextlib import suppress
from winreg import (
  ConnectRegistry,
  OpenKey,
  EnumValue,
  EnumKey,
  QueryInfoKey,
  QueryValue,
  KEY_READ,
  KEY_ALL_ACCESS,
  HKEY_LOCAL_MACHINE,
  HKEY_CURRENT_USER,
  HKEY_USERS,
  HKEY_CURRENT_CONFIG,
  HKEY_CLASSES_ROOT,
  REG_BINARY
)

# consts for unpacking shimcache binary
WIN10_STATS_SIZE = 0x30
WIN10_CREATORS_STATS_SIZE = 0x34
WIN10_MAGIC = b'10ts'

# const for converting FILETIME to UTC
WIN32_EPOCH = datetime(1601, 1, 1)

def time_(timestamp):
    """
        Goal:
        Timestamps returned by querying registry keys using winreg are FILETIME
        structure format. This is a function that converts the illegible timestamp
        returned from winreg to a more readable format.

        *** Time returned is UTC. Make sure it aligns with your current system ***
        *** settings, and be mindful of the time parameters you feed into the  ***
        *** program!                                                           ***
    """
    return WIN32_EPOCH + timedelta(microseconds = timestamp // 10)

def rot13(str_val:str):
    """
        Goal:

        This is a simple function that helps us decode the rot_13 string values
        inside the UserAssist registry key.
    """
    return encode(str_val, 'rot_13');

def get_subkeys(hkey, path, flags = 0):
    """
        Goal:
        If a particular registry key has multiple subkeys, and you don't want to 
        manually call the path to each individual subkey, this function will 
        return a list of all the subkeys.
    """
    with suppress(WindowsError, OSError), OpenKey(hkey, path, 0, KEY_READ | flags) as key:
        for i in count():
            yield EnumKey(key, i) 

def system_info():
    """
        Goal:
        This function gives us an overview of the systeminfo

        NAME_VALS:
        windows nt\currentversion has a giant list of values.
        This list shortens those values into only a handful that gives us more
        immediate and upfront information about the current system.
    """
    NAME_VALS = ['ProductName', 'ReleaseID', 'BuildLab', 'BuildLabEx', 'CompositionEditionID', 'RegisteredOrganization', 'RegisteredOwner', 'InstallTime']

    print("-" * 75)
    print("\nBasic System Information\n\n" + "-" * 75)
    with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName", 0, KEY_ALL_ACCESS) as key:
        num_vals = QueryInfoKey(key)[1]

        for i in range(num_vals):
            value = EnumValue(key, i)
            print(f"Computername\t\t\t{value[1]}")

    with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0, KEY_ALL_ACCESS) as key:
        num_vals = QueryInfoKey(key)[1]
        for i in range(num_vals):
            values = EnumValue(key, i)
            if values[0] in NAME_VALS:
                if values[0] == "InstallTime":
                    # print(f"{values[0]}\t\t\t{time_(values[1])}")
                    print(values[0], time_(values[1]), sep="\t" * 3)
                    continue
                print(*values[:-1], sep="\t" * 3)
    print("-" * 75)

def network_info():
    """
        Goal:
        This function gives us an overview of the Network Interface Cards

        NAME_VALS:
        TCPIP\Parameters\Interfaces\{interface} has a giant list of values.
        This list shortens those values into only a handful that gives us more 
        immediate and upfront information about the Network Interface Cards.
    """
    NAME_VALS = ['DefaultGateway', 'DhcpServer', 'DhcpIPAddress', 'DhcpNameServer', 'DhcpSubnetMask', 'DhcpDomain', 'Domain', 'IPAddress', 'NameServer', 'SubnetMask', 'RegisteredOwner', 'InstallTime']

    print("\nNetwork Adapter Information\n")
    for subkey in get_subkeys(HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"):
        with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\\" + subkey, 0, KEY_ALL_ACCESS) as key:
            num_vals = QueryInfoKey(key)[1]
            print("-" * 75)
            print(f"Network Interface Card: {subkey}\n" + "-" * 75)
            for i in range(num_vals):
                values = EnumValue(key, i)
                if values[0] in NAME_VALS:
                    print(*values[:-1], sep="\t" * 3)

def parse_shimcache(appCompatCache, ver_magic=WIN10_MAGIC, creators=False):
    """
        Goal: This function reads and unpacks binary data found on the shimcache
        and parses out relevant info. 
        
        *** A lot of code written here is derived from mandiant's shimcacheparser.py ***

        The functionality of unpacking the bytes data from inside the registry value
        requires a loop until the end of data, as the data is stored in a huge chunk.
    """

    if creators:
        appCompatCache_ = appCompatCache[WIN10_CREATORS_STATS_SIZE:]
    else:
        appCompatCache_ = appCompatCache[WIN10_STATS_SIZE:]

    data = BytesIO(appCompatCache_)

    while data.tell() < len(appCompatCache_):
        header = data.read(12)
        magic, crc32_hash, entry_len = unpack('<4sLL', header)

        entry_data = BytesIO(data.read(entry_len))

        path_length = unpack('<H', entry_data.read(2))[0]
        if path_length != 0:
            path = entry_data.read(path_length).decode('utf-16le', 'replace')
        else:
            path = 'Path not found...'

        low_dt, high_dt = unpack('<LL', entry_data.read(8))
        temp_dt = high_dt
        temp_dt <<= 32
        temp_dt |= low_dt
        last_modified = temp_dt

        print(path, time_(last_modified), sep="\t" * 3)

def parse_prefetch():
    """
        Goal: This function parses the prefetch files, granted that the prefetching is enabled in the
        registry. It returns two values, the filename of the prefetch, and the last accessed time.

        Note that there are other prefetch parsing tools out there that actually reads the binary data
        stored inside the prefetch files, and present much greater details about each. 
    """
    abs_root_dir = os.path.abspath(os.sep)
    prefetch_dir = os.path.join(abs_root_dir, 'windows', 'prefetch')
    
    print("Prefetch Entry:\t\t\tLast Execution:")
    with suppress(FileNotFoundError), os.scandir(prefetch_dir) as records:
        for record in records:
            if record.is_file():
                record_stats = record.stat()
                # os.stat() returns several values in a set. The 7th-index value happens to be the
                # st_atime, which is the last accessed time value. 
                print(record.name, datetime.utcfromtimestamp(record_stats[7]), sep='\t' * 3)

def user_behavior(min_time=WIN32_EPOCH, max_time=datetime.utcnow(), user_sid=""):
    """
        Goal:
        This function gives us an overview of the User Behavior by parsing out
        relevant artifacts from UserAssist, RecentDocs, MuiCache

        This function takes in the arguments min_time, max_time, and user_sid to carve out relevant 
        data within specific time frames, and pertinent to specific user's hive. 
        
        TODO: Default arguments 
        are set to get all data from #-#-#-#-#-#-1001.

        For UserAssist, we target 2 specific subkeys:
        {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} and {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}.
        This is a to-do item for the future, as the subkeys seem to be different for earlier
        versions of windows.
    """

    # print("\nUser Assist Values\n" + "-" * 75)
    # print("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\n" + "-" * 75)
    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_CURRENT_USER), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count", 0, KEY_ALL_ACCESS) as key:
    #     num_vals = QueryInfoKey(key)[1]
    #     print("Executable:\t\t\tLast Execution:")
    #     for i in range(num_vals):
    #         value = EnumValue(key, i)
    #         # time_(unpack("Q", value[1][60:68])[0])
    #         # As value[1] is the binary data stored with each value inside the UserAssist subkey,
    #         # we unpack bytes 60 - 68, which are timestamps for last execution and feed it through
    #         # our time_ function, which converts it to UTC time. Be mindful that the timestamps 
    #         # pulled from registry are UTC timestamps.
    #         print(rot13(value[0]), time_(unpack("Q", value[1][60:68])[0]), sep="\t" * 3)

    # print("\n" + "-" * 75)
    # print("{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\n" + "-" * 75)
    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_CURRENT_USER), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count", 0, KEY_ALL_ACCESS) as key:
    #     num_vals = QueryInfoKey(key)[1]
    #     print("Executable:\t\t\tLast Execution:")
    #     for i in range(num_vals):
    #         value = EnumValue(key, i)
    #         # time_(unpack("Q", value[1][60:68])[0])
    #         # As value[1] is the binary data stored with each value inside the UserAssist subkey,
    #         # we unpack bytes 60 - 68, which are timestamps for last execution and feed it through
    #         # our time_ function, which converts it to UTC time. Be mindful that the timestamps 
    #         # pulled from registry are UTC timestamps.
    #         print(rot13(value[0]), time_(unpack("Q", value[1][60:68])[0]), sep="\t" * 3)

    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_CURRENT_USER), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", 0, KEY_ALL_ACCESS) as key:
    #     num_vals = QueryInfoKey(key)[1]
    #     if num_vals != 0:
    #         print("\n" + "-" * 75)
    #         print("Recent Docs\n" + "-" * 75)
    #         for i in range(num_vals):
    #             value = EnumValue(key, i)
    #             print(*value[:-1], sep="\t" * 3)

    # print("\n" + "-" * 75)
    # print("MuiCache\n" + "-" * 75)
    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_CURRENT_USER), r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", 0, KEY_ALL_ACCESS) as key:
    #     num_vals = QueryInfoKey(key)[1]
    #     for i in range(num_vals):
    #         value = EnumValue(key, i)
    #         if value[0] == "LangID": continue
    #         print(*value[:-1], sep="\t" * 3)

    # print("\n" + "-" * 75)
    # print("Background Activity Monitor\n" + "-" * 75)
    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-881430183-2975666877-16831743-1001", 0, KEY_READ) as key:
    #     num_vals = QueryInfoKey(key)[1]
    #     print("Executable:\t\t\tLast Execution:")
    #     for i in range(num_vals):
    #         value = EnumValue(key, i)
    #         # time_(unpack("Q", value[1][60:68])[0])
    #         # As value[1] is the binary data stored with each value inside the UserAssist subkey,
    #         # we unpack bytes 60 - 68, which are timestamps for last execution and feed it through
    #         # our time_ function, which converts it to UTC time. Be mindful that the timestamps 
    #         # pulled from registry are UTC timestamps.
    #         if type(value[1]) == int: continue
    #         print(value[0], time_(unpack("Q", value[1][0:8])[0]), sep="\t" * 3)


    # *** USE Eric Zimmerman Tools manually for this shit ***
    # *** AMCACHE, SHIMCACHE                              ***
    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", 0, KEY_READ) as key:
    #     num_vals = QueryInfoKey(key)[1]
    #     print("Executable:\t\t\tLast Modified:")
    #     for i in range(num_vals):
    #         value = EnumValue(key, i)
    #         # time_(unpack("Q", value[1][60:68])[0])
    #         # As value[1] is the binary data stored with each value inside the UserAssist subkey,
    #         # we unpack bytes 60 - 68, which are timestamps for last execution and feed it through
    #         # our time_ function, which converts it to UTC time. Be mindful that the timestamps 
    #         # pulled from registry are UTC timestamps.
    #         if value[0] == "AppCompatCache":
    #             # print(unpack("Q", value[1])
    #             # print(value[1]) # How to unpack this long A$$ binary wtf?!
    #             if len(value[1]) > WIN10_STATS_SIZE and value[1][WIN10_STATS_SIZE:WIN10_STATS_SIZE+4] == WIN10_MAGIC:
    #                 parse_shimcache(value[1])
    #             elif len(value[1]) > WIN10_CREATORS_STATS_SIZE and value[1][WIN10_CREATORS_STATS_SIZE:WIN10_CREATORS_STATS_SIZE+4] == WIN10_MAGIC:
    #                 parse_shimcache(value[1], creators=True)

    with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters", 0, KEY_READ) as key:
        num_vals = QueryInfoKey(key)[1]
        for i in range(num_vals):
            value = EnumValue(key, i)
            if value[0] == "EnablePrefetcher" and value[1] == 3:
                parse_prefetch()

    # *** Just use SAMPARSER.py (dependents: python-registry || pip install python-registry) ***
    # *** to carve out info from the SAM... can't figure out how to do it using the built-in ***
    # *** winreg library =(                                                                  ***
    # for subkey in get_subkeys(HKEY_LOCAL_MACHINE, r"SAM"):
    #     print(subkey)
    #     with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SAM\\" + subkey, 0, KEY_ALL_ACCESS) as key:
    #         num_vals = QueryInfoKey(key)[1]
    #         for i in range(num_vals):
    #             value = EnumValue(key, i)
    #             print(*value[:-1], sep="\t" * 3)

def enum_key(hive, subkey:str):
    with suppress(WindowsError, OSError), OpenKey(hive, subkey, 0, KEY_ALL_ACCESS) as key:
        num_of_values, dt = QueryInfoKey(key)[1], QueryInfoKey(key)[2]
        print(f"Last Modified Time: {time_(dt)}\n")
        for i in range(num_of_values): # num_of_values
            values = EnumValue(key, i) # returns a tuple of 3 items. 
            if values[0] == "LangID" or values[2] == REG_BINARY: continue
            print(*values[:-1], sep="\t")

def persistence_info():
    # Run / RunOnce Keys
    # grab path directories from the registry
    # get os timestamps - Creation time?
    # if timestamp is between the user's timestamps, parse out the info
    print("HKCU Run Keys:\t\t\tLast Modified:\t\t\tLast Accessed:\t\t\tFile Created:")
    with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_CURRENT_USER), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0, KEY_READ) as key:
        num_vals = QueryInfoKey(key)[1]
        if num_vals:
            for i in range(num_vals):
                value = EnumValue(key, i)
                split_ = value[1].find("exe")
                path = (value[1][:split_+3]).replace('"','')
                print(value[0], datetime.utcfromtimestamp(os.stat(path)[8]), datetime.utcfromtimestamp(os.stat(path)[7]), datetime.utcfromtimestamp(os.stat(path)[9]), sep='\t' * 3)
                # print(value[0], os.stat(path), sep='\t' * 3)


if __name__ == "__main__":
    # # Connecting to the HKEY_LOCAL_MACHINE hive
    # with ConnectRegistry(None, HKEY_LOCAL_MACHINE) as hklm_hive:
    #     print("\nCurrent Version/Build Info")
    #     print("-"*50)
    #     enum_key(hklm_hive, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    #     print("\nSystem Environment Variables")
    #     print("-"*50)
    #     enum_key(hklm_hive, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
    #     print("\nStartup Applications")
    #     print("-"*50)
    #     enum_key(hklm_hive, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    # # Connecting to the HKEY_CURRENT_USER hive
    # with ConnectRegistry(None, HKEY_CURRENT_USER) as hkcu_hive:
    #     print("\nPreviously Ran Applications")
    #     print("-"*50)
    #     enum_key(hkcu_hive, r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache")
    # system_info()
    # network_info()
    # user_behavior()
    persistence_info()
    