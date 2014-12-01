Scapy experiment for measurement infrastructures (like RIPE Atlas) to probe multiple IP lists.

needs a local config file called 'ninja-server.conf' in yaml format. Example:

    ---
    ServerIP: 192.168.0.1
    ServerDomain: random-ip.emileaben.com

This code acts as a DNS server, and when it receives an A or AAAA request it returns an IP address from a specified list.

There is a default list (ips.txt) that is read from the same dir as the server is started from, or if it is queried in the form:

    <listname>.<serverdomain>

it will try to find an ips.txt file in the local <listname> directory, and serve IPs from there.

example (with config file above):

query for amsterdam-nl.random-ip.emilaben.com

will cause the server to look for an ip-list in the local ./amsterdam-nl/ directory. If it exists it will load it, randomize the list, and serve an IP from it. The next query for this name will get the next IP from the randomized list.
At the end of the list, it will be randomized again, and the first IP from the randomized list will be returned again.
