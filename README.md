# ROPHelper
A tool to assist in searching for ROP gadgets for syscalls.

Supports x86_64 ELF

### Install ropper
https://github.com/sashs/Ropper

### Usage
Run tool: ./ROPHelper.py

Enter file path as prompted.

Enter a syscall function name, or "list" to display syscall table.

Enter values for each parameter, one value at a time.

After entering the file path, you may use command "quit" at any time to exit the tool.

### Example

./ROPHelper.py

File path:

> /bin/ls

syscall:

> list

...

(the entire syscall table with parameters)

syscall:

> setreuid

2 args:

> 1000

rdi=0x3e8

...

(gadgets that could set rdi to 1000)

> 0

rsi=0x0

...

(gadgets that could set rsi to 0)

-----------------------------------------------------------------

rax=0x71

...

(gadgets that could set rax to 0x71)

...

(gadgets that contain instruction "syscall")

syscall:

> quit
