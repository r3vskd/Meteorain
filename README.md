[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome) <img src="https://img.shields.io/badge/Python-3.8-blue"> <img src="https://img.shields.io/badge/Status-Beta-orange"> <img src="https://img.shields.io/badge/Version-1-red"> <img src="https://img.shields.io/badge/Licence-MIT-yellowgreen">

<img src = 'https://raw.githubusercontent.com/r3vskd/Meteorain/main/images/Screenshot_2.png'></img>

:warning: This tool is only for educational purposes, use this responsibly :warning:

## Meteorain
Proof of concept to perform DDoS using DNS amplification (reflection) technique.

## What is a DNS amplification attack?
This DDoS attack is a reflection-based volumetric distributed denial-of-service (DDoS) attack in which an attacker leverages the functionality of open DNS resolvers in order
to overwhelm a target server or network with an amplified amount of traffic, rendering the server and its surrounding infrastructure inaccessible.

## Key Differences between general DDoS and DNS amplification technique:
- Targeted Resource: While a general DDoS attack aims to overwhelm any available resource (bandwidth, processing power, etc.),
  a DNS amplification attack specifically targets the DNS infrastructure.
- Amplification Factor: DNS amplification attacks leverage the amplification effect of DNS responses to magnify the volume of traffic directed at the target.
- Mitigation Techniques: Mitigating a DNS amplification attack may involve implementing measures such as rate limiting on DNS servers, using DNS response validation,
  and securing open DNS resolvers. Mitigating general DDoS attacks might involve deploying DDoS protection services, firewalls, and load balancers.

## Is possible to mitigate a DNS amplification attack?
Yes, mitigation options are limited due to the high amount of traffic generated, the Internet Service Provider (ISP) or other upstream infrastructure providers may not
be able to handle the incoming traffic without becoming overwhelmed. As a result, the ISP may blackhole all traffic to the targeted victim’s IP address.

## References:
- https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/
- https://blog.cloudflare.com/reflections-on-reflections/
- https://www.imperva.com/learn/ddos/ddos-attacks/
- https://www.exploit-db.com/exploits/44265

## Usage & installation:

``` pip install -r requirements.txt ```

``` python ./poc.py ```

## Example 

``` python ./poc.py -d example.com -s 8.8.8.8 -p 53 -f resolvers.txt -q 10 -i 1 -v ```

When performing DNS queries, your system typically uses a configured DNS resolver (which could be your ISP's DNS server or a custom DNS server like Google DNS - 8.8.8.8 or Cloudflare DNS - 1.1.1.1). However, with this script, you can override the default DNS resolver used by your system and specify a different DNS server using the --server_address parameter.

For instance, if you want to test how a specific DNS server resolves a domain name (e.g., example.com), you can use this parameter to specify the IP address or hostname of that DNS server.

Here's an example of how you might use this parameter in the script:

-d example.com specifies the domain to query (example.com).
-s 8.8.8.8 specifies the DNS server's address (in this case, Google's DNS server).
-p 53 specifies the port used for DNS queries (defaulting to port 53).
-f resolvers.txt is the file containing a list of DNS resolvers.
-q 10 sets the number of queries to send (in this case, 10 queries per resolver).
-i 1 sets the interval between queries to 1 second.
-v enables verbose mode to display detailed information about the queries and responses.

## Donation

Loved the project? You can buy me a coffee

<a href="https://www.buymeacoffee.com/r3vskd" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>
