# Memory-Forensics Using Volatility 3
This is some of ways to retrieve evidence through memory forensics. 

## Task Scheduler
Many of malware achieve its persistence through task scheduler like [LokiBot](https://attack.mitre.org/software/S0447/) , [Remsec](https://attack.mitre.org/software/S0125/) and etc.  

During incident response, one of things to look is task created.  

Steps you can try , bear in mind some of evidence may not be retrieve due to memory is too volatile.  
Before that you need to know structure of task scheduler:

(Info) Registry artifacts 

File system:   

* %systemroot%\System32\Tasks    
* %systemroot%\Tasks  

Registry:  

* HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks  
* HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree  

1. List Hive to get offset:  
```
python39 vol.py -f <mem_file> windows.registry.hivelist
```
Example Output in Console:
```
Offset  FileFullPath    File output
0xcd0fd540e000          Disabled
0xcd0fd5433000  \REGISTRY\MACHINE\SYSTEM        Disabled
0xcd0fd54da000  \REGISTRY\MACHINE\HARDWARE      Disabled
0xcd0fd5cec000  \Device\HarddiskVolume1\Boot\BCD        Disabled
0xcd0fd5cee000  \SystemRoot\System32\Config\SOFTWARE    Disabled
0xcd0fd905c000  \SystemRoot\System32\Config\DEFAULT     Disabled
0xcd0fd90f6000  \SystemRoot\System32\Config\SECURITY    Disabled
0xcd0fd9226000  \SystemRoot\System32\Config\SAM Disabled

```
2. From registry artifact we know task scheduler locate in Software Hive and its offset (0xcd0fd5cee000). Hence use the offset with a KEY(Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks) to filter :
```
python39 vol.py -f <mem_file> windows.registry.printkey --offset=0xffffcd0fd5cee000 --key="Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks" --recurse > dump_result.txt
```
3. Analyse the dump_result.txt to get suspicious task scheduler id-key and check with this command:  
```
python39 vol.py -f <mem_file> windows.registry.printkey --offset=0xffffcd0fd5cee000 --key="Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{5FE8D604-2E8E-41EC-A557-5A88F300A5D4}
```
id-key{5FE8D604-2E8E-41EC-A557-5A88F300A5D4} --> it can be many so yo need to loop to find one by one.

## Windows Event Log

