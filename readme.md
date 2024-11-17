# VTMonitor
VTMonitor is a syscall hooking tool for **specific threads** with Intel VT-x.  
This tool can intercept direct system calls such as SysWhispers.  
You can write syscall handlers to modify behaviour or monitor args.  

Perhaps multi-processing and multi-threading can be supported if appropriate handlers are written.  
At least, NtCreateUserProcess and NtCreateThreadEx must be handled.  

Please only use this for simple programs. ~~(VEH, SEH and others are not supported)~~  
VEH and SEH are supported but there is a possibility that Windows will hang in order to run kernel code in guest mode.  
If you dont need to use exception handling, please check "Base-Impl" tag.



## Using
```
sc create <servicename> binpath=<path to VTMonitor.sys> type=kernel
sc start <servicename>
VTMonitorClient.exe <target.exe>
```
## Environment
- VS2019
- Windows10 x64 20H2
- Only 64bit

## Example
Monitoring program call CreateProcessW to launch notepad  
![](img/example.png)

## Reference
- WSL1
- Hypervisor From Scratch
    - https://github.com/SinaKarvandi/Hypervisor-From-Scratch
- HAXM
    - https://github.com/intel/haxm
- Noah
    - https://github.com/linux-noah/noah

## License Information

This project uses the following third-party software licensed under the MIT License:

- [ept.cpp](VTMonitor/ept.cpp) - [Hypervisor-From-Scratch/Ept.c](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%208%20-%20How%20To%20Do%20Magic%20With%20Hypervisor!/Hypervisor%20From%20Scratch/MyHypervisorDriver/Ept.c)
- [ept.h](VTMonitor/ept.h) - [Hypervisor-From-Scratch/Ept.h](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%208%20-%20How%20To%20Do%20Magic%20With%20Hypervisor!/Hypervisor%20From%20Scratch/MyHypervisorDriver/Ept.h)
- [vmx.h](VTMonitor/vmx.h) - [Hypervisor-From-Scratch/Vmx.h](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%207%20-%20Using%20EPT%20&%20Page-level%20Monitoring%20Features/MyHypervisorDriver/MyHypervisorDriver/Vmx.h)
- [msr.h](VTMonitor/msr.h) - [Hypervisor-From-Scratch/Ept.h](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%208%20-%20How%20To%20Do%20Magic%20With%20Hypervisor!/Hypervisor%20From%20Scratch/MyHypervisorDriver/Ept.h)

The MIT License (MIT) applies to these files. The full text of the MIT License can be found in the header of each file.