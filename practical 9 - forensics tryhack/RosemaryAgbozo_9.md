#ROSEMARY AGBOZO - CYBER SECURITY 
#USING WINDOWS COMMAND LINE

#TASK 1

##Question 1:

Cheking the info:
**volatility -f victim.raw imageinfo**


INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (C:\Users\agboz\Downloads\volatility_2.6_win64_standalone\victim.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028420a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002843d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-05-02 18:11:45 UTC+0000
     Image local date and time : 2019-05-02 11:11:45 -0700


_Answer:_ At suggested profiles, more on the OS can be seen. So taking Win7SP1x64, you can conclude that the OS is Windows


##Question 2:
PID of search indexer

**volatility -f victim.raw --profile=Win7SP1x64 pslist**

0xfffffa8003367060 SearchIndexer.         2180    504     11      629      0      0 2019-05-02 18:03:32 UTC+0000

_Answer:_ 2180

##Question 3: 
What is the last directory accessed by the user?

**volatility -f victim.raw --profil=Win7SP1x64 shellbags**


***************************************************************************
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0
Last updated: 2019-04-27 10:48:33 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     deleted_files  2019-04-27 10:30:26 UTC+0000   2019-04-27 10:38:24 UTC+0000   2019-04-27 10:38:24 UTC+0000   NI, DIR                   Z:\logs\deleted_files
***************************************************************************


_Answer:_ deleted_files



#TASK 2

##Question 1:
There are many suspicious open port, which is it ?(protocol:port)

**volatility -f victim.raw --profile=Win7SP1x64 netscan**

C:\Users\agboz\Downloads\volatility_2.6_win64_standalone>volatility -f victim.raw --profile=Win7SP1x64 netscan
Volatility Foundation Volatility Framework 2.6
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x5c201ca0         UDPv4    0.0.0.0:5005                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c201ca0         UDPv6    :::5005                        *:*                                   2464     wmpnetwk.exe   

_Answer:_ udp:5005


#Question 2:
Vads tag and execute protection are strong indicators of malicious processes, can you find which are they?

**volatility -f victim.raw --profile=Win7SP1x64 malfind**

Process: explorer.exe Pid: 1860 Address: 0x3ee0000
Process: svchost.exe Pid: 1820 Address: 0x24f0000
Process: wmpnetwk.exe Pid: 2464 Address: 0x280000

_Answer:_ 1860;1820;2464






#TASK 3 - IOC SAGA

Extracting the infected processes

**volatility -f victim.raw --profile=Win7SP1x64 memdump  --pid=1820,1860,2464 --dump-dir PIDdump**

************************************************************************
Writing explorer.exe [  1860] to 1860.dmp
************************************************************************
Writing svchost.exe [  1820] to 1820.dmp
************************************************************************
Writing wmpnetwk.exe [  2464] to 2464.dmp

After extracting, I expoerted the folder to Kali Linux and performed the remaining operations. 

#Question 1:

'www.go****.ru' 

**strings 1820.dmp | grep 'www.go.....ru'**

Hint: Site is a little naughty 

_Answer:_ www.goporn.ru

#Question 2:

'www.i****.com'

**strings 1820.dmp | grep 'www.i.....com'**

Hint: Do you like football? 

_Answer:_ www.ikaka.com

#Question 3:

'www.ic******.com'

**strings 1820.dmp | grep 'www.ic.......com'**

Hint: Very strong IOC

_Answer:_ www.icsalabs.com


#Qustion 4: 

202.***.233.***

**strings 1820.dmp | grep '202\....\.233\....'**

_Answer:_ 202.107.233.211

#Question 5:

***.200.**.164
**strings 1820.dmp | grep '...\.200\...\.164'**

_Answer:_  209.200.12.164

#Question 6:

209.190.***.***

**strings 1820.dmp | grep '209.190..'**

_Answer:_ 209.190.122.186

#Question 7:

What is the unique environmental variable of PID 2464?

**volatility -f victim.raw --profile=Win7SP1x64 envars --pid=2464**

Volatility Foundation Volatility Framework 2.6
Pid      Process              Block              Variable                       Value
-------- -------------------- ------------------ ------------------------------ -----
    2464 wmpnetwk.exe         0x00000000002c47a0 ALLUSERSPROFILE                C:\ProgramData
    2464 wmpnetwk.exe         0x00000000002c47a0 APPDATA                        C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming
    2464 wmpnetwk.exe         0x00000000002c47a0 CommonProgramFiles             C:\Program Files\Common Files
    2464 wmpnetwk.exe         0x00000000002c47a0 CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
    2464 wmpnetwk.exe         0x00000000002c47a0 CommonProgramW6432             C:\Program Files\Common Files
    2464 wmpnetwk.exe         0x00000000002c47a0 COMPUTERNAME                   VICTIM-PC
    2464 wmpnetwk.exe         0x00000000002c47a0 ComSpec                        C:\Windows\system32\cmd.exe
    2464 wmpnetwk.exe         0x00000000002c47a0 FP_NO_HOST_CHECK               NO
    2464 wmpnetwk.exe         0x00000000002c47a0 LOCALAPPDATA                   C:\Windows\ServiceProfiles\NetworkService\AppData\Local
    2464 wmpnetwk.exe         0x00000000002c47a0 NUMBER_OF_PROCESSORS           1
    2464 wmpnetwk.exe         0x00000000002c47a0 OANOCACHE                      1
    2464 wmpnetwk.exe         0x00000000002c47a0 OS                             Windows_NT
    2464 wmpnetwk.exe         0x00000000002c47a0 Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\


_Answer:_ OANOCACHE




