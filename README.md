# Introduction to Docker and Kubernetes


## What is Namespaces?

Namespaces are a feature of the Linux kernel that partitions kernel resources such that one set of processes sees one set of resources while another set of processes sees a different set of resources.

As of kernel version 4.10, there are 7 kinds of namespaces.

### The namespaces API:
**clone()** and **unshare()**: system calls creates a new process or moves the calling process to a new
namespace. If the flags argument of the call specifies one or more of the CLONE_NEW* flags listed below, then new namespaces are created for each flag, and the child process is made a member of those namespaces.

**setns()**: system call allows the calling process to join an existing namespace.

```
# get namespaces of init process
ls -l /proc/1/n

# namespaces of PID
ls -l /proc/<PID>/ns/
```

### Mount (mnt):
* Mount namespaces provide isolation of the list of mount points seen by the processes in each namespace instance.
* the processes in each of the mount namespace instances will see distinct single-directory hierarchies.
* /proc/<PID>/mountinfo provide info about mnt namespace

### Process ID (PID):
* Provides processes with an independent set of process IDs (PIDs) from other namespaces.
* The first process created in a PID namespace is assigned the process id number 1 and receives most of the same special treatment as the normal init process.
* termination of this PID 1 process will immediately terminate all processes in its PID namespace and any descendants.
* initial PID namespace is able to see all processes, although with different PIDs than other namespaces will see processes with.

### Network (net):
* Network namespaces virtualize the network stack.
* On creation it contains only a loopback interface.
* Each network interface (physical or virtual) is present in exactly 1 namespace and can be moved between namespaces.
* Each namespace will have a private set of IP addresses, its own routing table, socket listing, connection tracking table, firewall, and other network-related resources.

### Interprocess Communication (ipc):

* IPC namespaces isolate processes from inter-process communication. (Pipes, FIFOs, Pseudoterminals, Sockets, POSIX message queues, POSIX shared memory, Signals)
* The Linux IPC namespace partitions shared memory primitives like named shared memory blocks and semaphores, as well as message queues.
* The IPC namespace prevents processes in one container from accessing the memory on the host or in other containers.
* sharing IPC namespace is often used when the latency associated with network or pipe based IPC drags software performance below requirements. The best examples of shared memory based IPC usage is in scientific computing and some popular database technologies like PostgreSQL.
* Docker creates a unique IPC namespace for each container by default.

Here is a nice example about shred IPC https://github.com/allingeek/ch6_ipc


### UTS

### Control group (cgroup)

### User ID (user)


### Example:

![alt text](NS-intro.png)

First create a docker container and extract its content to local directory:
```bash
docker run -id golang bash
docker export <ID> -o go_root.tar
mkdir go_root
tar xf go_root.tar --ignore-command-error -C go_root/
```

Then create a network namespace:
```bash
ip netns add net_demo
```

Use `unshare` (wrapper in util-linux to call `unshare` syscall) to run bash in chroot environment and new namespaces:
```bash
unshare --mount --uts --ipc --net=/var/run/netns/net_demo --pid --fork --user --map-root-user chroot go_root /bin/bash

unshare --mount --uts --ipc --net=/var/run/netns/net_demo --pid --fork --setgroups=allow  chroot go_root /bin/bash
# inside the container
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /tmp
```

Then cgroups will be used to limit the memory usage. Create a new cgroup:
```bash
mkdir /sys/fs/cgroup/memory/demo
# limit memory usage by 100mb and disable swappiness
echo "100000000" > /sys/fs/cgroup/memory/demo/memory.limit_in_bytes
echo "0" > /sys/fs/cgroup/memory/demo/memory.swappiness
```

Get the init process of the container:
```
ps aux | grep /bin/bash | grep root
```

Add it to demo cgroup:
```
echo <PID> > /sys/fs/cgroup/memory/demo/tasks
```

mknod -m 644 /dev/urandom c 1 9

Test the memory limit using this python code:
```python
f = open("/dev/urandom", "r")
data = ""

i=0
while True:
    data += f.read(10000000) # read 10mb
    i += 1
    print "%dmb" % (i*10)
```


ip link add veth1 type veth peer name eth0
ip link set eth0 netns net_demo
ip addr add 172.16.99.1/24 dev veth1
ip link set veth1 up
ip netns exec net_demo ip addr add 172.16.99.100/24 dev eth0
ip netns exec net_demo ip link set lo up
ip netns exec net_demo ip link set eth0 up
ip netns exec net_demo ip route add default via 172.16.99.1
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -P FORWARD DROP
iptables -F FORWARD
iptables -t nat -F
iptables -t nat -A POSTROUTING -s 172.16.99.100/24 -o ens3 -j MASQUERADE
iptables -A FORWARD -i ens3 -o veth1 -j ACCEPT
iptables -A FORWARD -o ens3 -i veth1 -j ACCEPT

To clean the network namespace:
```bash
umount /run/netns/net_demo
ip netns del net_demo
```

capabilities


sudo cgcreate -a bork -g memory:mycoolgrou


sudo setcap CAP_MKNOD=ep /home/user/rsync
