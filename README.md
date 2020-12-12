# ContiUnpacker
An automatic unpacker for a Conti sample


## Context

* This was inspired by James Bennett's blog [post](https://www.fireeye.com/blog/threat-research/2020/12/using-speakeasy-emulation-framework-programmatically-to-unpack-malware.html) on how to programmatically unpack malware.


* This unpacker unpacks this specific Conti ransomware I found on [MalwareBazaar](https://bazaar.abuse.ch/sample/03b9c7a3b73f15dfc2dcb0b74f3e971fdda7d1d1e2010c6d1861043f90a2fecd/).


## Requirement
* Python 3
* Speakeasy


## How it works

* The unpacker uses the [Speakeasy](https://github.com/fireeye/speakeasy) Emulation Framework to run and unpack the sample.

* When I manually unpacked this, I noticed that the sample called **VirtualAlloc** to allocate memory, wrote the unpacked PE file to it, and called **VirtualProtect** on the **.text** region before executing it.

* From this, I halted the simulation at the first **VirtualProtect** call, dumped the PE file out, and mapped it accordingly to fix the IAT.

## Usage

### Running with Command Prompt

```
python ContiUnpacker.py -f conti.dll -o <output_file>
```

## Image

![alt](/image/ContiUnpacker1.png)


![alt](/image/ContiUnpacker2.png)


## Note

**Please don't actually run this malware I included unless you know what you're doing. I'm not responsible if you end up encrypting your machine!**

Also, I noticed that the function calls are a bit different on Speakeasy emulator compared to when running on x64dbg. 
During the VirtualProtect call, everything should technically be written into the allocated memory already, but that's not the case...

Apparently, only parts of the **.rdata** section is written, so the dumped executable won't be able to run. 

I can't figure out why this is happening because Speakeasy is pretty weird, so this unpacker does not work 100%.

However, I'll still keep it here in case anyone wants to refer to this when writing their own unpacker using Speakeasy!

## Acknowledgement

James T. Bennett - https://www.fireeye.com/blog/threat-research/2020/12/using-speakeasy-emulation-framework-programmatically-to-unpack-malware.html

FireEye's Speakeasy Emulation Framework - https://github.com/fireeye/speakeasy
