# link-watcher - automatically select active link between two routers

This is proof-of-concept.

Two routers connected by multiple links in active and backup state need to automatic switching between them.
One router act as server and default gateway for other client router, which announce all subnets and additional
routes on its interfaces.

Client send "keep-alive" UDP packets signed by shared secret SHA256 on all connected interface and wait
acknowledge signed response from server. If server/client has no such packets more than two keep-alive pediod,
then server reset all routes to client on last active connection and wait from client to select another work
connection and select it as active.

```
                        Client side                                          Server side

                    +----------------+                                    +---------------+
Local subnets       |                | 10.248.248.2          10.248.248.1 |               |
                    |           eth1 x---------------/optic/--------------x eth2     eth0 x---/ Internet
  10.20.20.0/22 /   |                | 10.248.249.2          10.248.249.1 |               |   /    or
 172.31.13.0/24 /---x eth0    vlan10 x---------------/wifi/---------------x eth3     eth1 x---/   LAN
192.168.12.0/24 /   |                | 10.248.250.2          10.248.250.1 |               |
                    |           tun1 x-------------/OpenVPN/--------------x tun1          |
                    |                |                                    |               |
                    +----------------+                                    +---------------+
```

Client side routing table:
```
ip route add default via 10.248.248.1 dev eth1

or

ip route add default via 10.248.249.1 dev vlan10

or

ip route add default via 10.248.250.1 dev tun1
```

Server side routing table:
```
ip route add 10.20.20.0/22 via 10.248.248.2 dev eth2
ip route add 172.31.13.0/24 via 10.248.248.2 dev eth2
ip route add 192.168.12.0/24 via 10.248.248.2 dev eth2

or

ip route add 10.20.20.0/22 via 10.248.249.2 dev eth3
ip route add 172.31.13.0/24 via 10.248.249.2 dev eth3
ip route add 192.168.12.0/24 via 10.248.249.2 dev eth3

or

ip route add 10.20.20.0/22 via 10.248.250.2 dev tun1
ip route add 172.31.13.0/24 via 10.248.250.2 dev tun1
ip route add 192.168.12.0/24 via 10.248.250.2 dev tun1
```

## TODO

- [ ] - add options in program
- [ ] - add signal handler (exit, switch channels)
- [ ] - turn on/off automatic failover
- [ ] - syslog messages
- [ ] - statistics
- [ ] - make one struct for connection (not arrays)
- [ ] - check for errors, memleaks, other issues
