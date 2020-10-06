import requests

LinCheck_update = 'Privesc_Tools/LinCheck/'

LinCheck_url = [
    'https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh',
    'https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh',
    'https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh',
    'https://raw.githubusercontent.com/1N3/PrivEsc/master/linux/scripts/linux_checksec.sh',
    'https://github.com/1N3/PrivEsc/blob/master/linux/scripts/linux_security_test',
    'https://raw.githubusercontent.com/WazeHell/PE-Linux/master/PE.sh',
    'https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh',
    'https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py',
]

WinCheck_update = 'Privesc_Tools/WinCheck/'

WinCheck_url = [
    'https://raw.githubusercontent.com/M4ximuss/Powerless/master/Powerless.bat',
    'https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1',
    'https://raw.githubusercontent.com/Arvanaghi/SessionGopher/master/SessionGopher.ps1',
    'https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1',
    'https://raw.githubusercontent.com/BleepSec/Check-Service-Paths/master/Check-Service-Paths.ps1',
    'https://raw.githubusercontent.com/enjoiz/Privesc/master/privesc.ps1',
    'https://raw.githubusercontent.com/carlospolop/winPE/master/winPE.bat',
    'https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1',
]


def update(base_directory, url):
    file = url.split('/')
    file_name = file[-1]
    print('\n\t[#] Downloading File: {}'.format(file_name.split('.')[0]))
    file2update = base_directory + '{}'.format(file_name)
    with open(file2update, 'w') as updater:
        session = requests.session()
        file2download = session.get(url)
        updater.write(file2download.text)
        updater.close()
        session.close()
        print('\n\t[#] Done Updating File: {}'.format(file_name.split('.')[0]))


def main():
    update_option = input('[?] Do You Want To Update The Tools? (Y/N) ')

    if update_option.lower() == 'y':
        print("""\n[?] What You to Update? 
    1. Linux Tools
    2. Windows Tools
    3. ALL """)
        valid_input = True
        while valid_input:

            what2update = int(input('[?] Select Number: '))
            if what2update == 1:
                print('\n[*] Updating Linux Tools ')
                for x in LinCheck_url:
                    update(LinCheck_update, x)
                print('[*] Done Updating Linux Tools')
                valid_input = False

            elif what2update == 2:
                print('\n[*] Updating Windows Tools ')
                for x in WinCheck_url:
                    update(WinCheck_update, x)
                print('[*] Done Updating Linux Tools')
                valid_input = False

            elif what2update == 3:
                print('\n[*] Updating ALL Tools')
                for x in LinCheck_url:
                    update(LinCheck_update, x)
                for x in WinCheck_url:
                    update(WinCheck_update, x)
                print('[*] Done Updating ALL Tools')
                valid_input = False
            else:
                print('[!] Enter the Right Option')
    else:
        print('\n[#] Starting The Privesc Server...')


if __name__ == '__main__':
    main()
