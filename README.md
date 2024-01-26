# SeedLabs 2.0 - Firewall Exploration Lab

This repository contains solution to the [Firewall Exploration Lab](https://seedsecuritylabs.org/Labs_20.04/Networking/Firewall/).

#### Setup and Instructions: 
- [Cloud/VM Setup Options](https://seedsecuritylabs.org/labsetup.html)
- [Install Seed VM on VirtualBox (Recommended)](https://github.com/seed-labs/seed-labs/blob/master/manuals/vm/seedvm-manual.md)
- [Instructions for the Lab](https://seedsecuritylabs.org/Labs_20.04/Files/Firewall/Firewall.pdf)

## Solution
This lab revolves mostly around Linux iptables and netfilter. Download and unzip the the [LabSetup.zip](https://seedsecuritylabs.org/Labs_20.04/Networking/Firewall/) file inside the Seed VM. The lab environment is ready and now is a good time to give the instructions a read especially for easily running the containers and some code which is already good to go for a few tasks.
 
## Task 1: Implementing a Simple Firewall

### Task 1.A: Implement a Simple Kernel Module

Use the sample code provided in the ``hello.c`` file. Then run the following commands to insert and remove the module and to print kernel ring buffer:
  
```sh
>> make
>> sudo insmod hello.ko
>> sudo rmmod hello.ko
>> dmesg
```

Note: Note: For loading different files as modules using make again and again, use make clean first to clean up the previously generated files and use make again to load the fresh files.

### Task 1.B: Implement a Simple Firewall using Netfilter

We have 3 subtasks here. The sample code in the provided ``seedFilter.c`` file covers the basics of netfilters and can be used for the first subtask. For the other two subtasks, the code needs to changed.

#### Subtask 1:

For this task we need to block the UDP packets generated by the VM towards
``8.8.8.8`` which is also Google’s DNS IP Address. The sample code provided is capable of accomplishing this task. What the code does in essence is that it filters the packets with the destination address ``8.8.8.8`` and the destination ``port 53`` using the ``blockUDP`` function.

Run the following commands to make and insert the ``seedFilter`` module as well as to check if it works:
```sh
>> make
>> sudo insmod seedFilter.ko
>> dig 8.8.8.8

```

The ``dig 8.8.8.8`` command should give a 'connection timed out; no servers could be reached' message in the output if everything went well.

#### Subtask 2:

In this task, we have to add the functionality of printing packet information with each hook function, to observe the order in which the hook functions are executed. For this, we need to make some modifications to the original sample code in order to achieve this. Refer to the ``seedFilter-task1-subtask2.c`` file for the code.

Explanation for the code:

This module employs netfilter hooks to intercept network packets at various stages of processing, thereby facilitating the observation and logging of pertinent information about the packets. The ``printInfo`` function, registered at multiple netfilter hook points, meticulously extracts details such as source and destination IP addresses, the specific protocol employed (be it TCP, UDP, ICMP, or other), and the precise hook point within the network stack. Upon initialization, the module utilizes the ``registerFilter`` function to seamlessly integrate itself into the kernel, thereby enabling the packet processing function to be invoked at designated hook points. Conversely, the ``removeFilter`` function facilitates the graceful removal of the module by unregistering the previously established hooks. This module thus serves as a dynamic tool for monitoring and gaining insights into network traffic at distinct stages of packet processing within the Linux kernel.

Commands to make, insert and test the module:
```sh
>> make clean
>> make
>> sudo insmod seedFilter.ko
>> ping www.nyu.edu
>> dmesg
```

Additional information about the netfilter hooks that you might find useful:

- NF_INET_PRE_ROUTING: This hook is invoked before the routing decision is made. It occurs right after a packet has been received by the network interface, but before the kernel decides where to forward the packet.
- NF_INET_LOCAL_IN: This hook is invoked when the packet is destined for the local system. It occurs after the routing decision has been made, and the packet is meant for local delivery.
- NF_INET_FORWARD: This hook is invoked for packets that are being forwarded to another destination. It occurs after the routing decision has been made but before the packet is sent out.
- NF_INET_LOCAL_OUT: This hook is invoked when a packet is generated by the local system. It occurs before the routing decision is made for locally generated packets.
- NF_INET_POST_ROUTING: This hook is invoked after the routing decision has been made and just before the packet is transmitted by the network interface.

#### Subtask 3:

For this subtask, we have to prevent other computers from establishing a ping or a telnet connection with the VM. This needs to be done by two different hook functions registered under the same hook. Also, we are required to start one of the containers with the IP Address ``10.9.0.5`` and try and ping/telnet the VM to test our firewall. Refer to the ``seedFilter-task1-subtask3.c`` file for the code.

Explanation for the code:

This Linux kernel module serves as a packet filter by leveraging netfilter hooks to intercept and scrutinize network packets during the NF_INET_PRE_ROUTING stage, which occurs prior to the routing decision. The module defines two distinct packet processing functions, namely ``preventPing`` and ``preventTelnet``, each associated with a separate netfilter hook (``hook1`` and ``hook2``, respectively). The ``preventPing`` function discerns ICMP Echo (Ping) packets and takes a preventive measure by dropping them, accompanied by a corresponding log message. Similarly, the ``preventTelnet`` function identifies TCP packets destined for port 23 (Telnet) and enforces a block, documenting the attempt through a log entry. The ``registerFilter`` function undertakes the initialization and registration of these hooks, and the complementary ``removeFilter`` function disengages them gracefully upon module removal. By focusing on the pre-routing stage, the module aims to thwart specific network activities, such as Ping and Telnet, providing a customizable and early filtering mechanism within the Linux kernel.

Commands to get the containers running and know their IDs:
```sh
>> docker compose up
>> dockps
```

Commands to make and insert the module:
```sh
>> make clean
>> make
>> sudo insmod seedFilter.ko
```
Ping and telnet the VM from one of the running containers to see the module working; both ping and telnet from any of the containers to the VM should fail. 

## Task 2: Experimenting with Stateless Firewall Rules

This task involves experimenting with the firewall rules. 

**Note: Before you run each of the tasks below, make sure to reset the firewall rules by running these commands:**
```sh
>> iptables -F
>> iptables -P OUTPUT ACCEPT
>> iptables -P INPUT ACCEPT
``` 

### Task 2.A: Protecting the Router

For this task, we just have to run the commands provided to us in the document, on the ``seed-router`` container which is basically acting as a router here and we have to see whether we can ping and telnet the router container after we have applied the rules in it.

### Task 2.B: Protecting the Internal Network

In this task, we are required to create rules on the router firewall such that they satisfy the following criteria:

1. Outside hosts cannot ping internal hosts.
2. Outside hosts can ping the router.
3. Internal hosts can ping outside hosts.
4. All other packets between the internal and external networks should be blocked.

To accomplish this task, configure the firewall using the following commands:
```sh
>> iptables -A INPUT -i eth0 -p icmp --icmp-type echo-request -j ACCEPT
>> iptables -A OUTPUT -o eth0 -p icmp --icmp-type echo-reply -j ACCEPT
>> iptables -A FORWARD -i eth1 -o eth0 -p icmp --icmp-type echo-request -j ACCEPT
>> iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-reply -j ACCEPT
>> iptables -A FORWARD -i eth0 -o eth1 -p icmp --icmp-type echo-request -j DROP
>> iptables -A FORWARD -i eth1 -o eth0 -j DROP
>> iptables -A FORWARD -i eth0 -o eth1 -j DROP
```

The firewall should now be able to enforce the given conditions.

### Task 2.C: Protecting Internal Servers

In this task, we are required to protect the TCP servers inside the internal network (``192.168.60.0/24``). We are required to enforce the following conditions using firewall rules in the router:

1. All the internal hosts run a telnet server (listening to port 23). Outside hosts can
only access the telnet server on 192.168.60.5, not the other internal hosts.
2. Outside hosts cannot access other internal servers.
3. Internal hosts can access all the internal servers.
4. Internal hosts cannot access external servers.
5. In this task, the connection tracking mechanism is not allowed. It will be used in a later task.

To accomplish this task, configure the firewall using the following commands:
```sh
>> iptables -A FORWARD -i eth0 -p tcp -d 192.168.60.5 --dport 23 -j ACCEPT
>> iptables -A FORWARD -i eth1 -p tcp -s 192.168.60.5 --sport 23 -j ACCEPT
>> iptables -P FORWARD DROP
```

## Task 3: Connection Tracking and Stateful Firewall

### Task 3.A: Experiment with Connection Tracking

There is a mechanism inside the kernel known as ``conntrack`` which allows us to
trace connections. Tracing connections is very useful for creating stateful firewalls. This task requires to experiment with the ``conntrack`` command with various types of packets such as UDP, TCP and ICMP packets.

#### ICMP Experiment:
For this experiment, we have to run the ``conntrack -L`` command on the router
container before, after and while pinging one container from another.

- Expected observations: There will be no entries for the connection before the ping begins, the entries will start to show up during the ping session, the entries will stay for a few seconds after the ping session, and after a few seconds there will again be no entries.

#### UDP Experiment:
For this experiment, we have to run the ``conntrack -L`` command on the router while listening on UDP mode of ``netcat`` on one container while giving it data over UDP from another container.

- Expected observations: Results will be similar to those of the ping experiment, there will be no entries of tracking before the connections, entries will be visible during the connection, they will stay for a few seconds after the connection is terminated, after which they disappear.

#### TCP Experiment:
For this experiment, we have to listen over TCP mode of ``netcat`` on ``192.168.60.5`` and send it data from ``10.9.0.5`` over TCP as well, all while running ``conntrack -L`` command again and again on the router.

- Expected observations: After the TCP ``netcat`` session is terminated, the entries for the connections will stay there for more than 2 minutes after which they will disappear. This is probably because TCP is a stateful protocol by itself and it will also be seen that the status of the connection tracking was ``TIME_WAIT`` after the connection was terminated indicating that it will stay there for some time.

### Task 3.B: Setting up a Stateful Firewall

The goal for this task is same as Task 2.C but the only difference is that the firewall is now allowed to be stateful and internal machines can connect to external machines.

To accomplish this task, configure the firewall using the following commands:
```sh
>> iptables -A FORWARD -i eth0 -p tcp -d 192.168.60.5 --dport 23 --syn -m conntrack --ctstate NEW -j ACCEPT 
>> iptables -A FORWARD -i eth1 -p tcp --syn -m conntrack --ctstate NEW -j ACCEPT
>> iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
>> iptables -A FORWARD -p tcp -j DROP
>> iptables -P FORWARD ACCEPT
```

## Task 4: Limiting Network Traffic

The number of packets passing through the firewall can also be limited. For this experiment, we have been given two commands/rules (in the instructions document) to be run on the router, and we have to run just one line of the command/rule for the first time and run both the given lines of the command/rule for the second time. After each run, we also have to ping ``192.168.60.5`` from ``10.9.0.5`` and note our observations and differences.

- Expected observations: There will not be much effect on limiting the number of packets going through the firewall upon adding just the first rule. But when the second line will be added as a rule to the router, the ping will become very slow and lossy after a few seconds. 

From my understanding, this is because when we run just the first line of the code adding the first rule, we tell the firewall about the time limit but not what to do if a packet exceeds the time limit. The second line makes it much more clear and hence it works well and actually limits the number of packets coming through the firewall. Thus, the second line of the rules is indeed very important here. 

## Task 5: Load Balancing

There are two methods of load balancing as described in the given material: Round Robin mode (nth mode) and Random mode. We have to load balance three UDP servers running in the internal network using both of these load balancing methods. Details on how to set these two types of load balancing (rules and commands with
usages) have been provided in the reference document and can be followed to easily get this task done.

Commands for setting up Round Robin (nth) mode:
```sh
>> iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode nth --every 3 --packet 0 -j DNAT --to-destination 192.168.60.5:8080
>> iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode nth --every 2 --packet 0 -j DNAT --to-destination 192.168.60.6:8080
>> iptables -t nat -A PREROUTING -p udp --dport 8080 -m statistic --mode nth --every 1 --packet 0 -j DNAT --to-destination 192.168.60.7:8080 
```

Commands for setting up Random mode: 
```sh
>> iptables -t nat -A PREROUTING -p udp - -dport 8080 \
-m statistic - -mode random - -probability 0.1 \
-j DNAT - -to-destination 192.168.60.5:8080 

>> iptables -t nat -A PREROUTING -p udp - -dport 8080 \
-m statistic - -mode random - -probability 0.2 \
-j DNAT - -to-destination 192.168.60.6:8080

>> iptables -t nat -A PREROUTING -p udp - -dport 8080 \
-m statistic - -mode random - -probability 0.7 \
-j DNAT - -to-destination 192.168.60.7:8080 
```
All hosts get equal number of packets when Round Robin (nth) mode is set up whereas the Random Mode of load balancing provides a probabilistic approach to selecting packets for NAT. Each packet has a probability of being selected based on the specified probability value. This allows for a more randomized distribution of network traffic, which can be beneficial for load balancing purposes.

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)
