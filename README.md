# Pestilence

Pestilence is the second of a 4 project suite about viruses. Now that we have solved the problems of self-replicating programs, we will now try to hide and obfuscate to make reverse-engineers job hrder.

### Disclaimer

This project is purely pedagogical and is not made to any illegal or irresponsible use.

## Infection/Control Flow Hijacking/Spreading

See [Famine](https://github.com/alagroy-42/Famine/blob/master/README.md)

I actually removed strategy one to implement the crypter more easily, now infection is always happening in the data segment.

## Evasion mesures

### "Anti-AV"

To escape a potential AV, `Pestilence` will loop through all the `/proc/<pid>/status` files and check the name of the program. If any corresponds to the program blacklist, `Pestilence` will stop and return control to original program.

### Anti-debug

To escape a potential debugger and avoid compromising, `Pestilence` will check the `TracerPid` value in `/proc/self/status`. If it's not null, `Pestilence` will get the pid and kill it ;)
Even though this process is obfuscated, it is still possible for someone debugging to try to pretend that `TracerPid` is null to be able to trace the rest of the execution, that's why it is obfuscated.


## Encryption

The virus body (everything in the data segment) is encrypted using the [RC4 algorithm](https://en.wikipedia.org/wiki/RC4). With that encryption, the only code readable that a static tool can analyze is the `mprotect` chunk of code and the decryptor.

## Obfuscation

To hide virus from both static (objdump, IDA etc...) and dynamical (debugger, emulation ...) analysis, the infection routine is obfuscated. If a good reverse-engineer manage to get all the code decrypted and can see the whole virus, there are some tricks all along to try to deceive them.

### Fake jumps

This technique consist in using a first jump to jump one byte forward and use this byte to insert a raw byte, `0xe9` in our case. Being the `jmp` opcode, most of the tools will then interpret the code that we jumped on as an address and get all of it wrong.

### Push/Ret

This technique consists simply to push the address of the next instruction on the stack and then use a ret to get it executed. That way, a lot of malware analysis tools will think that the ret is the end of the function and will consider the rest as dead code, but it is actually getting executed. It also hides it from a lot of debugger that stop disassembling after the `ret` instruction.

### Dead code

Dead code is a very simple technique that consists in jumping on the next "real" instruction and put some code in between. That code will never be executed and might complicate the task of a reverse-engineer.


## Counter-measures

Being conscious of all these tricks, if one wants to be able to study the whole virus body, it is doable by :
- 1) Evading the debugger evasion
- 2) Setting a breakpoint on the virus entrypoint and letting the vbirus decryptoer do its workto see the decrypted code 
- 3) Searching for each fake jumps sequence (0xeb 0x01 0xe9 => jmp +1, byte '0xe9') and replace it with nops (0x90).
- 4) Doing the same for the push/ret sequence, it is a bit longer but it is constant and only used for the trick.
- 5) Once those tricks are removed, following the code flow will be enough to remove all the dead code
- 6) Enjoy the reverse, the code is clean
