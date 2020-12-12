# ContiUnpacker
An automatic unpacker for a Conti sample


## Context

* This was inspired by James Bennett's blog [post](https://www.fireeye.com/blog/threat-research/2020/12/using-speakeasy-emulation-framework-programmatically-to-unpack-malware.html) on how to programmatically unpack malware.


* This unpacker unpacks this specific Conti ransomware I found on [MalwareBazaar](https://bazaar.abuse.ch/sample/03b9c7a3b73f15dfc2dcb0b74f3e971fdda7d1d1e2010c6d1861043f90a2fecd/).


**NOTE: Please don't actually run this malware I included unless you know what you're doing. I'm not responsible if you end up encrypting your machine!**

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

## Acknowledgement

James T. Bennett - https://www.fireeye.com/blog/threat-research/2020/12/using-speakeasy-emulation-framework-programmatically-to-unpack-malware.html

FireEye's Speakeasy Emulation Framework - https://github.com/fireeye/speakeasy
