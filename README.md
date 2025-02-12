# Debugger Evasion
> By **Oorth**
<pre align="center">

 ____    ____ ____  __ __   ___    ___   ____ ____      ____ __ __  ___   __  __   ___   __  __
 || \\  ||    || )) || ||  // \\  // \\ ||    || \\    ||    || || // \\ (( \ ||  // \\  ||\ ||
 ||  )) ||==  ||=)  || || (( ___ (( ___ ||==  ||_//    ||==  \\ // ||=||  \\  || ((   )) ||\\||
 ||_//  ||___ ||_)) \\_//  \\_||  \\_|| ||___ || \\    ||___  \V/  || || \_)) ||  \\_//  || \||
                                                                                               
</pre>

## !! Disclaimer !!
Hi, This project is still under development and still vulnerable to kernel level debuggers.
>~~Don't worry it will work flawlessly against almost all debuggers ( ik not every debugger :( but I am working on it )~~
## Overview
So this is a c++ program which also uses assembly for some functions, which could be used inside your code :)
This program is able to evade all user-level debuggers using techniques such as ->


  Debugger Detection:
>   1) Reading various PBE flags
>   2) Checking Heap patterns
>   3) Detecting Hardware Breakpoints
>   4) Detecting Software Breakpoints

  Anti Attach:
>   1) Self-Debugging
>   2) TLS Callback Anti-Debugging
>   3) Anti-Attach Using Debug Object Check
>   4) Parent Process Check
>   5) Exception-Based Anti-Attach
      
  Anti Memory Scanning:
>    Coming soon :)


## How to Compile?

### evd_debug.exe:
```markdown
  cl /EHsc .\evd_debug.cpp debug_check.obj /link user32.lib Advapi32.lib /OUT:evd_debug.exe
```
### debug_check.asm:
```markdown
  ml64 /c /Fl debug_check.asm
```

## The End
So people have fun stay safe, If you have further ideas or suggestions go on I am all Ears.

