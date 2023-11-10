# Meteorain
Script to perform DDoS using DNS amplification (reflection) technique.

# What is a DNS amplification attack?
This DDoS attack is a reflection-based volumetric distributed denial-of-service (DDoS) attack in which an attacker leverages the functionality of open DNS resolvers in order to overwhelm a target server or network with an amplified amount of traffic, rendering the server and its surrounding infrastructure inaccessible.

# Is possible to mitigate a DNS amplification attack?
Yes, mitigation options are limited due to the high amount of traffic generated, the Internet Service Provider (ISP) or other upstream infrastructure providers may not be able to handle the incoming traffic without becoming overwhelmed. As a result, the ISP may blackhole all traffic to the targeted victim’s IP address.

# Key Differences between general DDoS and DNS amplification technique:
- Targeted Resource: While a general DDoS attack aims to overwhelm any available resource (bandwidth, processing power, etc.),
  a DNS amplification attack specifically targets the DNS infrastructure.
- Amplification Factor: DNS amplification attacks leverage the amplification effect of DNS responses to magnify the volume of traffic directed at the target.
- Mitigation Techniques: Mitigating a DNS amplification attack may involve implementing measures such as rate limiting on DNS servers, using DNS response validation,
  and securing open DNS resolvers. Mitigating general DDoS attacks might involve deploying DDoS protection services, firewalls, and load balancers.

|==============================================|
# REFERENCES:
- https://www.cloudflare.com/learning/ddos/dns-amplification-ddos-attack/
- https://blog.cloudflare.com/reflections-on-reflections/
- https://www.imperva.com/learn/ddos/ddos-attacks/
