from itertools import count
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

def rot13(str_val:str):
    """
        Goal:
        This is a simple function that helps us decode the rot_13 string values
        inside the UserAssist registry key.
    """
    return encode(str_val, 'rot_13');

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
    return WIN32_EPOCH + timedelta(microseconds=timestamp // 10)

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

def user_behavior(min_time=WIN32_EPOCH, max_time=datetime.utcnow(), user_sid=""):
    """
        Goal:
        This function gives us an overview of the User Behavior by parsing out
        relevant artifacts from UserAssist, RecentDocs, MuiCache

        For UserAssist, we target 2 specific subkeys:
        {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} and {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}.
        This is a to-do item for the future, as the subkeys seem to be different for earlier
        versions of windows.
    """
    # print("\nUser Assist Values\n" + "-" * 75)
    # print("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\n" + "-" * 75)
    # with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_CURRENT_USER), r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count", 0, KEY_ALL_ACCESS) as key:
    #     num_vals = QueryInfoKey(key)[1]
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

    print("\n" + "-" * 75)
    print("Background Activity Monitor\n" + "-" * 75)
    with suppress(WindowsError, OSError), OpenKey(ConnectRegistry(None, HKEY_LOCAL_MACHINE), r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21-881430183-2975666877-16831743-1001", 0, KEY_READ) as key:
        num_vals = QueryInfoKey(key)[1]
        for i in range(num_vals):
            value = EnumValue(key, i)
            # time_(unpack("Q", value[1][60:68])[0])
            # As value[1] is the binary data stored with each value inside the UserAssist subkey,
            # we unpack bytes 60 - 68, which are timestamps for last execution and feed it through
            # our time_ function, which converts it to UTC time. Be mindful that the timestamps 
            # pulled from registry are UTC timestamps.
            if type(value[1]) == int: continue
            print(value[0], time_(unpack("Q", value[1][0:8])[0]), sep="\t" * 3)

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
    user_behavior()
    