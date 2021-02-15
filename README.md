# vsock_poc
Investigating the bug behind CVE-2021-26708


This repo contains a small writeup about CVE-2021-26708, and how this bug can be turned into a Use After Free write primitive. The PoC here is not a full exploit, but just my harnass I used when trying to investigate this bug. It can sucessfully use a entry from the kmalloc-64 cache after it is freed, but doesn't have any code to groom memory and place something of interest in the slot.

This is a fun bug was reported by [@a13xp0p0v](https://twitter.com/a13xp0p0v). It caught my eye because the patch was so simple, just preventing a reference to `vsk->transport` from being obtained outside of the lock in 5 different places.

TODO: writeup the process.
