# Research-Dirty-Pipe
CVE 2022-0847 (Dirty Pipe)
Video: https://www.youtube.com/watch?v=af0PGYaqIWA

## What is it?

Dirty Pipe vulnerability is a Linux kernel vulnerability that allows the ability of non-privileged users to overwrite read-only files. The vulnerability is due to an uninitialized “pipe_buffer.flags” variable, which overwrites any file contents in the page cache even if the file is not permitted to be written, immutable, or on a read-only mount, including CD-ROM mounts. The page cache is always writable by the kernel and writing to a pipe never checks any permissions. An extensive write-up on the Dirty Pipe vulnerability can be found in the reference links at the end of this blog.

## Why is this important? 

This enables attackers to perform privilege escalation by overwriting data in arbitrary read-only files and injecting code from unprivileged processes to privileged processes. This can make Linux and Android systems vulnerable to a multitude of malware and other exploits, including ransomware.  

## Who is affected? 

This vulnerability affects endpoints running Linux with a kernel version 5.8 or higher. 

## Patched after? 

This vulnerability has been patched in the following versions:
5.16.11
5.15.25
5.10.102

More informantion: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847

Dirty pipe checker: https://github.com/basharkey/CVE-2022-0847-dirty-pipe-checker

POC: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

