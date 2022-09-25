---
# Google Summer of Code 2022 - The NetBSD Foundation <br/> Final Submissions: Emulating missing linux syscalls
---

## Abstract

As the title suggests, this project concentrates on adding missing system calls
in the Linux emulation layer of the NetBSD Kernel. The Linux emulation layer, 
referred to as the compat_linux layer, is an in-kernel ABI that lets the user
interact with the NetBSD Kernel through system calls with prototypes exactly as
their Linux equivalent. This binary emulation happens with the help of a mapping
function. The kernel performs the mapping operation, linking a Linux system call
to the corresponding NetBSD one.

## Implementation Plan

During the application process itself, through various iterations of my
proposal, I had chosen to implement **splice(2)** and **sendfile(2)**
in the compat_linux layer of the NetBSD Kernel. Throughout the
community-bonding period my mentor and I looked at other
unimplemented system calls too, but we decided to go ahead with these two.
After this, my mentor and I had an extensive discussion to finalize the
implementation plan for the project, and we decided in favor of a generic
system call that will transfer data from the file descriptor, *fd_in*,
to the out file descriptor, *fd_out*, inside the kernel space.  
<p align="center">
ssize_t splice(int fd_in, off_t off_in, int fd_out, off_t off_out,
size_t len);  
</p>
The plan had been to make this generic implementation support both
splice(2) and sendfile(2). We also decided to go for a bottom-up
approach, i.e., to implement these calls as native system calls in the
NetBSD Kernel and then add hooks to Linux compat layer to support them
later. The main reason behind this choice was the presence of a testing
mechanism, ATF (atf(7)), for the core NetBSD kernel.

## Work Done

-	The work done for the system call has been commited to the [trunk branch](https://github.com/cosmologistPiyush/emul-linux-syscalls/tree/trunk) of this repository.
-	The file which contains the main code is [src/sys/kern/sys_splice.c](https://github.com/cosmologistPiyush/emul-linux-syscalls/blob/trunk/sys/kern/sys_splice.c).
-	For a more concrete information about the exact work done please refer to
[GSoC22-TNF-FinalSubmission.patch](https://github.com/cosmologistPiyush/emul-linux-syscalls/blob/trunk/GSoC22-TNF-FinalSubmission.patch)
-	For more general information about this repository have a look at the [README.md](https://github.com/cosmologistPiyush/emul-linux-syscalls/blob/trunk/README.md)

#### Until Mid-Term

My mentors had advised me to start with a simple implementation that could serve
as proof of concept. Once we had that implementation, I could have built on
top of it. Therefore, I had planned to have a successful barebones
implementation tested and running for the mid-term evaluation. For this, I wrote
a simple version of the **splice()** system call itself, just with a
user-provided excess buffer and no offsets:  
<p align="center">
ssize_t splice(int fd_in, int fd_out, size_ nbytes, void \*excess_buffer,
size_t \*buffer_size);  
</p>
The *excess_buffer* and *buffer_size* were used in this version to notify when a
short-write occurred. Though I wanted to test this version of the call for
multiple descriptor types, I was only able to do so for regular files.

#### Mid-Term to End-Term

After the mid-term evaluation, I had quite a chunk of work left.
Nevertheless, as a more transparent implementation existed, it was
straightforward to build on top of it. I immediately started with different test
cases, which took up most of the time. As it required jumping in and out of the
kernel to adjust variables and minor bugs, it took me longer than I had
estimated. A week before the final evaluation, I applied for an extension to be
able to finish the project with ease and with great code quality.  

Given this extension, I first concentrated on finishing the entire
system call implementation in the kernel. In the last week and a half, I
restored the functionality to the one originally planned, wrote the
documentation, and added more and more test cases.

As of now, there are a total of 15 test cases which all pass making the system
call a success. The call has also been exposed to the NetBSD libc, along with a
**sendfile(2)** wrapper.

## Challenges

This project was significantly extensive compared to my previous project. Hence,
I did struggle with a few things at the start.

-   I was unfamiliar with the vnode/VFS architecture. Therefore, I spent
    a considerable amount of time educating myself. I also looked into
    FFS to better understand the architecture.

-   Another issue I had, was purely logistical, which was setting up a
    cross-debugger for the NetBSD Kernel.

-	Due to difficulties with the debugger even after setting it up, I ended up
	using **printf()**s which required recompiling of kernel every time, making
	things a bit slower.

But other than this, I enjoyed working on the project. The NetBSD code is so
well written and documented that it makes understanding the kernel code
moderately easy.

## Next Steps

I believe that there is still some work left. Right now, we have a bit more than
just a proof of functionality, but there still are edges to trim, test cases to
add, and some polishing required for different use cases to have robust
functionality. It would be an absolute pleasure of mine to keep up with this
work even after the official project is over, and also keep contributing to The
NetBSD Foundation on more such exciting projects.

## Thanks

Warmest thanks to my mentor Stephen Borrill, for helping me navigate this
project. Special thanks to Taylor R. Campbell, Joerg Sonnenberger, and all the
developers of The NetBSD Community, who have helped me throughout this project.
I would also like to express my heartfelt gratitude to The NetBSD Foundation for
giving me the opportunity to contribute once again.
