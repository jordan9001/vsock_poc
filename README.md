# vsock_poc
Investigating the bug behind CVE-2021-26708


This repo contains a small writeup about CVE-2021-26708, and how this bug can be turned into a Use After Free write primitive. The PoC here is not a full exploit, but just my harness I used when trying to investigate this bug. It can successfully use a entry from the kmalloc-64 cache after it is freed, but doesn't have any code to groom memory and place something of interest in the slot.

This is a fun bug reported by [@a13xp0p0v](https://twitter.com/a13xp0p0v). It caught my eye because the patch was so simple, just preventing a reference to `vsk->transport` from being obtained outside of the lock in 5 different places.
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c518adafa39f37858697ac9309c6cf1805581446

Below is a short walkthrough of the process for going from the patch to a use-after-free primitive that could be used for exploitation.

## Environment Setup
I downloaded the linux kernel 5.10.13, and manually undid the patch shown above. For more information on building and running the kernel, the following is a good reference.

https://fedoraproject.org/wiki/Building_a_custom_kernel

I also modified the boot parameters to enable debugging of the kernel with kgdb. Using gdb with the vmlinux file I had built earlier, I had all of the kernel symbols for the main kernel, but not for any loadable kernel modules. The code associated with the vulnerability was not loaded by default, but would be [loaded into the kernel](https://elixir.bootlin.com/linux/v5.10.13/source/net/socket.c#L1408) when the PF_VSOCK family is used (depending on how you built your kernel).

To get the symbols in kgdb for loaded modules, I made sure I used the vsock socket at least once, then I used `sudo cat /proc/modules | grep vsock` to get the base addresses of the associated modules. In gdb I would then do something like `(gdb) add-symbol-file ./net/vmw_vsock/vsock.ko 0xffffffffc0567000` to make gdb aware of where in memory that ko file's symbols are. `vsock.ko` and `vmw_vsock_virtio_transport_common.ko` were the two most relevant.

## Hunting the Primitive
It is fun to work backward from patches because unlike lots of vulnerability hunting, you know for a fact you are looking in the right spot already. In this case we know from the patch that a reference to the transport is saved before the `sock_lock` is obtained. We can safely expect the vulnerability to be due to the transport changing, but the old reference is used.

In this kind of a scenario we would hope that the transport itself would be a dynamically allocated object that can be freed and replaced with some other object inbetween the obtaining of the reference and the lock being held. Unfortunately when we track the lifetimes of the relevant transports implemented by the other modules, they seem to all be in global memory. So we are going to be looking some level deeper for items used when out of scope.

#### The Free pt. 1
Looking in `af_vsock.c`, we can find two places where the `vsk->transport` is modified. In `vsock_assign_transport` and `vsock_deassign_transport`. In `vsock_assign_transport` we can see that if there is a different existing transport, then `vsock_deassign_transport` is called before placing the new transport. 
If we look at the possibilities for the `vsk->transport->destruct(vsk)` call [here](https://elixir.bootlin.com/linux/v5.10.13/source/net/vmw_vsock/af_vsock.c#L411) we see that both the loopback and the virtio transports will just `kfree` the `vsk->trans` parameter. Bingo! If we can find (1) path to this call that can race with (2) a vulnerable function that uses a transport reference from before it was destructed to access the `vsk->trans`, then we will have our primitive.

Looking for a path to `vsock_deassign_transport`, we see it called from `vsock_sk_destruct` or `vsock_assign_transport`. `vsock_sk_destruct` is set as the `sock->destruct` function and so calls to `__sys_close`, or other availible calls along the destruction path like `sock_put`, `sock_close`, or `vsock_release` can end up here.

The most relevant path to `vsock_assign_transport` is through vsock_stream_connect, but requires the socket to be in a specific few states, and only ends up calling `vsock_deassign_transport` if the transport would change. And it would replace the `vsk->trans` parameter if we don't end up with a NULL new transport.

#### The Use
Before we go too far down finding which path to the free is right for us, we want to determine that there is a valid path that uses the `vsk->trans` member with a invalid reference to a destructed transport. We can methodically check every spot where the transport is used with a possibly invalid reference. Tracing down those holes we can find ones where the `vsk->trans` is used. The best path seems to be through `vsock_stream_setsockopt`, when `transport->notify_buffer_size` writes to an offset inside the `vsk->trans` for loopback and virtio transports. If the trans is freed when used there, we get a nice write of a u32 to an offset of 0x28 in a kmalloc-64 allocation.

#### The Race
The use of that `vsock_stream_setsockopt` as a primitive depends on a race where inbetween obtaining the reference to the transport, and obtaining the `sock_lock`. That is a small window, and there are a lot of instructions to get there. So here we can use a cool feature in linux called the userfaultfd to make a better chance for ourselves. This mechanism lets us handle pagefaults in usermode at our leisure. With this we can have a thread (the gater) that will obtain the sock_lock and then access some user memory and cause a page fault. We can keep that thread paused (with the lock still held) as long as we want. Other threads that try to obtain that lock will stay there until we let the gater go and release the lock. We can line up our thread that will end up doing the destruct, and out thread that will use the invalid reference. Both will wait on the `sock_lock`, and now we have a great chance to win the race. If the thread doing the destruct is chosen to next obtain the lock, then our setsockopt call will complete afterward. It will use the vsk->trans pointer after it has been freed (and replaced).

If we the setsockopt call goes first instead, we lose the race, but can safely try the whole process again.

#### The Free pt. 2
When trying to build this I spent a while going down the wrong path. I tried to get the `vsock_deassign_transport` called via close and timeouts, but ran into lots of reference count checks that delayed the actual destruction until it was too late. When I finally switched over to looking at the `vsock_assign_transport` path, it came together quickly. In order to satisfy the requirements, we first connect to `VM_ADDR_CID_LOCAL`, when there is no listening server. This will give us the loopback transport, but then when our connection timesout or fails our state will return to `SS_UNCONNECTED`. This allows us to do another connect to a address greater than VM_ADDR_CID_HOST, which will cause our transport to change, destructing our existing transport and causing the free. It is important we do this when there is not actually any registered `transport_g2h` or `transport_h2g`, so our new transport will be NULL, and our freed reference will remain in the vsk->trans.

## Exploitation
With all of that lined up we get a reliable use-after-free that could be used for privilege escalation.

This repo is only about us getting up to the initial use-after-free. But now we have a primitive to write a value at an offset in the kmalloc-64 cache where the `virtio_vsock_sock` was previously allocated. I decided to stop the walkthrough there because, what, do I have to do everything around here?


