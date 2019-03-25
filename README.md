# metamorph

Old metamorphic engine working on a 32bit x86 (no FPU/SIMD instructions) architecture and a 32bit windows Portable Executable.
Can disassemble, mutate, and assemble back binary executables by patching code/data references and addressing tables.
Doesn't support DLLs, interpreted executables or other weird stuff.
References that are outside main control flow are guessed using static analysis, there is no guarantee that mutated file will still work
in all possible flows.

Engine was used as a Proof of Concept to show injection of a simple position independent routine that
calls MessageBox inside a random position into main control flow of given host executable.

Tested succesfully back in 2008 against 32bit notepad.exe and other small executables.

Heavily inspired by some of the greatest metamorphic engines and viruses of early 2000s like Z0mbie MistFall and MetaPHOR.
Using customized YAD as a single line instruction disassembler.

vx.netlux.org for ever <3
