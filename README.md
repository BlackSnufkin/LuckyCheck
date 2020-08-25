# LuckyCheck
* Modular Privesc ToolBox Add or Remove Tools as you want just with 4 lines and 6 lines for make it look good ;)
* For each tool it will generate a output file.
* Merge all files into one Big ASS report and REMOVE duplicate.
* Ziping the generated files and send them to the Privesc Server via PUT Method
### Usage:
```
usage: LinCheck.py [-h] -i  [-b | -a | -f]

Example: LinCheck.py -i 127.0.0.1 -b (Basic Scan)

optional arguments:
  -h, --help      show this help message and exit
  -i, --server   The Privesc Server IP.
  -b, --basic     Run Basic LinCheck Scan (2 Tools) .
  -a, --advanced  Run advanced LinCheck Scan (4 Tools).
  -f, --full      Run Full LinCheck Scan (8 Tools).
```
### To read the reports:
```
unzip LinCheck-Bascic.zip
less -R LinCheck-Basic-report.txt
```
### How To Add NewTool:
* Create funcation where all the tools funcations are with the new tool you want
* Select where you want to add this new tool, Basic Advanced or Full
* Just add the function NewTool(base_url) where you want this funcation to run
* Same Work in Both Files WinCheck and LinCheck 
```
def NewTool(base_url): 
    NewTool = "Some Command that run the tool"
    NewTool_url = base_url + "the name of the tool that on the Privesc Server"
    print('\n[+] Running NewTool Scan ')
    LinCheck(cmd=NewTool, url=NewTool_url, output_file="NewTool.txt", input_file="NewTool.sh")
    print('[$] Done NewTool Scan.\n')
   ```
### How to Remove Tools:
* Select the tool you want to remove
* Delete the funcation from the source and from the Bascic Advanced and Full

### Credits & Tools:
WinCheck Tools:
* [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
* [winPE](https://github.com/carlospolop/winPE)
* [Seatbealt](https://github.com/Lexus89/SharpPack/tree/master/Seatbelt)
* [J.A.W.S](https://github.com/411Hall/JAWS)
* [Powerless](https://github.com/M4ximuss/Powerless)
* [Invoke-PrivescCheck](https://github.com/itm4n/PrivescCheck)
* [SharpChromium](https://github.com/djhohnstein/SharpChromium)
* [SharpUp](https://github.com/GhostPack/SharpUp)
* [Watson](https://github.com/rasta-mouse/Watson)
* [Sherlock](https://github.com/rasta-mouse/Sherlock)
* [SessionGopher](https://github.com/Arvanaghi/SessionGopher)
* [Check-Service-Paths](https://github.com/BleepSec/Check-Service-Paths)
* [Invoke-Privesc](https://github.com/enjoiz/Privesc)

LinCheck Tools:
* [linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)
* [LinEnum](https://github.com/rebootuser/LinEnum)
* [PE-Linux](https://github.com/WazeHell/PE-Linux)
* [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
* [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
* [linux_security_test](https://github.com/1N3/PrivEsc/tree/master/linux/scripts)
* [linux_privesc](https://github.com/1N3/PrivEsc/tree/master/linux/scripts)
* [linux_checksec](https://github.com/1N3/PrivEsc/tree/master/linux/scripts)
















