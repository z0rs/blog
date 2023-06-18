---
title: Potential Subdomain Takeover
author: Eno
date: 2019-06-15 00:00:00 +0800
---

![thumbnail](https://raw.githubusercontent.com/z0rs/z0rs.github.io/master/takeover/takeOver.png)

### Abstract

This report examines a potential subdomain takeover attack on the `link.coca-cola.com` subdomain, which leads to the sendgrid.net email marketing service. Subdomain takeover attacks exploit improperly registered subdomains, posing security risks to a company's systems and data. The study aims to raise awareness of these risks and provides recommendations for prevention. The analysis involves examining DNS records using publicly available tools. The results indicate a potential subdomain takeover attack on link.coca-cola.com, with a `medium-level` CVSS v3.1 score. Recommendations include updating subdomain configurations and regularly monitoring unused subdomains.

### Introduction

Subdomain takeover attacks exploit unused or incorrectly registered subdomains to gain control and exploit vulnerabilities in a company's systems. The `link.coca-cola.com` subdomain, used in Coca-Cola's email marketing campaigns, redirects to sendgrid.net, making it susceptible to subdomain takeover attacks. These attacks can lead to significant data loss and reputation damage for companies.

The report analyzes the potential for subdomain takeover attacks on link.coca-cola.com and provides preventive recommendations. DNS record analysis and an examination of the subdomain's configuration in the sendgrid.net service were conducted to gather insights.

### Analysis

DNS analysis reveals that the `link.coca-cola.com` subdomain has a CNAME record pointing to `link.v27424770.c308478841.e.marketingautomation.services`, which ultimately leads to the SendGrid.net service. This suggests a potential subdomain takeover attack. Publicly available tools were used to assess the security risks. The analysis indicates that link.coca-cola.com is managed by sendgrid.net but lacks proper DNS registration by Coca-Cola. Irresponsible parties could exploit this unregistered subdomain for subdomain takeover attacks.

Multiple methods were employed to analyze potential subdomain takeover attacks on `link.coca-cola.com`, including DNS record analysis and an examination of `sendgrid.net` subdomain configuration. Research on common attacker techniques was also conducted to understand possible exploitation scenarios and develop preventive strategies.

### CVSS Score

The analysis indicates a medium-level CVSS v3.1 score of 5.3 for the potential subdomain takeover attack on link.coca-cola.com. The attack's impact can lead to service abuse.

- CVSS v3.1 Score: 5.3 (Medium)

The CVSS Vector for this potential subdomain takeover attack on `link.coca-cola.com` is ***CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N***. The vector reveals that the attack can be carried out over the network, has low attack complexity, requires no privileges, doesn't require user interaction, has an unchanged scope limited to the successfully attacked subdomains, doesn't affect data confidentiality, affects data integrity at a low level, and doesn't affect data availability.

Based on the analysis, it is evident that the `link.coca-cola.com` subdomain, redirecting to `sendgrid.net`, is not officially registered by Coca-Cola and lacks proper DNS records. This makes it vulnerable to subdomain takeover attacks. Proactive measures are necessary to enhance subdomain settings and prevent such attacks.

### Impact

Subdomain takeover attacks compromise the security of enterprise systems and data. Attackers can manipulate data sent through the subdomain after gaining control. The attack's impact includes reputational harm and potential financial losses if sensitive data, access credentials, or personal information is compromised. In the case of link.coca-cola.com, a subdomain takeover could lead to email abuse and pose a threat to user data security.

### Recommendation

To prevent subdomain takeover attacks, proper subdomain management is crucial. This includes regular monitoring and removal of unused subdomains, avoiding CNAME subdomains for untrusted services, using unique and unpredictable subdomains, and implementing secure DNS configurations with DNSSEC.

### Conclusion

The conclusion of this report is to provide a deeper understanding of potential subdomain takeover attacks on the subdomain link.coca-cola.com connected to the email marketing service sendgrid.net, and to provide appropriate recommendations to prevent such attacks from occurring. This report is expected to help security professionals and enterprises better understand the security risks associated with subdomain takeover attacks, and be able to take effective measures to protect corporate systems and data.

### Closing

Subdomain takeover attacks pose security risks to systems and data. This report emphasizes the importance of understanding and preventing such attacks. By implementing recommended measures, companies can safeguard their reputation, customer trust, and financial well-being. Effective subdomain management and countermeasures are essential in mitigating the risk of subdomain takeover attacks on enterprise systems and data.

### Bibliography

- [Barker, J. (2019). Subdomain Takeover Vulnerability Explained. The Hacker News.](https://thehackernews.com/2019/05/subdomain-takeover-vulnerability.html)
- [Chen, H., Hu, X., Yang, W., & Huang, X. (2020). Subdomain takeover attacks: Analysis, detection and defense. Journal of Network and Computer Applications, 152, 102547.](https://doi.org/10.1016/j.jnca.2020.102547)
- [Dogan, F., & Akgun, M. 2021. An analysis of subdomain takeover vulnerabilities and their detection methods. Journal of Cybersecurity, 7(1), tyab002.](https://doi.org/10.1093/cybsec/tyab002)
- [Shaw, D., & Jordan, M. 2019. What is a subdomain takeover and why does it matter? Cloudbric.](https://www.cloudbric.com/blog/2019/08/what-is-a-subdomain-takeover-and-why-does-it-matter/)
- [OWASP 2021 Subdomain takeover.](https://owasp.org/www-community/attacks/Subdomain_takeover)
- [SendGrid 2021.](https://sendgrid.com/)
