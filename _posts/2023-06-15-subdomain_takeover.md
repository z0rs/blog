---
title: Potential Subdomain Takeover
author: z0rs
date: 2023-06-15 00:00:00 +0800
categories: [bugbounty, host]
tags: [writeups, takeover]
---

![thumbnail](https://raw.githubusercontent.com/z0rs/z0rs.github.io/master/takeover/takeOver.png)

### List of contents:
- Abstract
- Introduction
- Analysis
- CVSS Score
- Impact
- Recommendation
- Conclusion
- Closing
- Bibliography

### Abstract

This report discusses a potential subdomain takeover attack on the link.coca-cola.com subdomain, leading to the email marketing service sendgrid.net. A subdomain takeover attack can compromise the security of a company's systems and data because it takes advantage of a subdomain that is not properly registered. The purpose of this study is to provide an understanding of the potential security risks caused by subdomain takeover attacks and provide recommendations for preventing these attacks. The methodology used in this study is the analysis of DNS records on the link.coca-cola.com subdomain using publicly available tools. The results showed that there is a potential subdomain takeover attack on the subdomain link.coca-cola.com which leads to the sendgrid.net service with `CVSS v3.1: 5.3 (Medium)` Score and `CVSS Vector: 3.1/AV:N/AC:L/PR :N/UI:N/S:U/C :N/I:L/A:N` The impact of this attack can be abuse of the service. The recommendations given are to update the subdomain configuration and monitor regularly the unused subdomains.

### Introduction

Subdomain takeover is an attack technique that exploits unused or incorrectly registered subdomains to take control of the subdomain and exploit any security vulnerabilities that may exist in the company's system. In the email marketing service `sendgrid.net`, there is a subdomain `link.coca-cola.com` which is used by Coca-Cola company in their email marketing campaigns. However, this subdomain redirects to the "sendgrid.net" subdomain which allows the potential for subdomain takeover attacks.

Subdomain takeover attacks can result in significant losses for a company, both in terms of data loss and the company's reputation being disrupted by criminal activity.

Therefore, the purpose of this report is to analyze the potential for subdomain takeover attacks on the `link.coca-cola.com` subdomain and provide recommendations to prevent such attacks. This research was conducted using DNS record analysis on the `link.coca-cola.com` subdomain and an analysis of the configuration and settings of the subdomain in the `sendgrid.net` service.

The results of this research can provide input for companies and security professionals in preventing subdomain takeover attacks on email marketing services and other services used by companies.

### Analysis

From the results of DNS analysis, it was found that the subdomain **`link.coca-cola.com`** has a CNAME record that points to **`link.v27424770.c308478841.e.marketingautomation.services`**, which then points to the service SendGrid.net. This suggests a potential subdomain takeover attack on the `link.coca-cola.com` subdomain leading to the SendGrid.net service.

To find out the potential security risks that could occur as a result of a subdomain takeover attack on the `link.coca-cola.com` subdomain, an analysis was performed using publicly available tools. Based on the analysis results, it was found that the subdomain `link.coca-cola.com` is a subdomain under the management of the `sendgrid.net` service and does not have a correct DNS record. In addition, this subdomain is a subdomain that is not officially registered by the Coca-Cola company and can be exploited by irresponsible parties to carry out subdomain takeover attacks.

This study uses several methods to analyze potential subdomain takeover attacks on the subdomain link.coca-cola.com. The first method is DNS record analysis using publicly available tools, such as nslookup and dig, to obtain information about the IP address and DNS configuration of the subdomain. The second method is an analysis of the configuration and settings of the subdomains in the sendgrid.net service, which can provide information about whether the subdomain is registered under a valid account or not.

In addition, research is also carried out on the techniques and methods commonly used by attackers in carrying out subdomain takeover attacks. This is done to understand ways in which an attacker might exploit vulnerabilities in the link.coca-cola.com subdomain and take control of that subdomain. Thus, appropriate strategies and recommendations can be developed to prevent such attacks.

### CVSS Score

The results show that there is a potential subdomain takeover attack on the subdomain link.coca-cola.com which leads to the sendgrid.net service with CVSS v3.1: 5.3 (Medium) The impact of this attack can lead to service abuse.

- CVSS v3.1 Score: 5.3 (Medium)

Based on the analysis that has been done, the potential for takeover subdomain attacks on the `link.coca-cola.com` subdomain has a CVSS v3.1 Score of 5.3 (Medium). This score is based on factors such as the possible impact on enterprise systems and data, the vulnerabilities being exploited, and the complexity of the attack required to achieve success.

- Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N

CVSS Vector is a vectorized representation of the CVSS score which shows the characteristics of the vulnerability. Based on the analysis that has been done, the vector for potential takeover subdomain attacks on the `link.coca-cola.com` subdomain

- AV:N (Attack Vector: Network) indicates that the attack can be carried out over the network.
- AC:L (Attack Complexity: Low) indicates that the attack requires conditions that facilitate the attack.
- PR:N (Privileges Required: None) indicates that the attack can be performed without requiring privileges.
- UI:N (User Interaction: None) indicates that the attack can be carried out without user interaction.
- S:U (Scope: Unchanged) indicates that the impact of the attack is limited to the subdomains that were successfully attacked.
- C:N (Confidentiality: None) indicates that the vulnerability does not affect data confidentiality.
- I:L (Integrity: Low) demonstrated that the vulnerability could affect data integrity on successfully attacked subdomains.
- A:N (Availability: None) indicates that the vulnerability does not affect data availability.

Based on the results of the analysis, the `link.coca-cola.com` subdomain is a subdomain that points to the `sendgrid.net` subdomain which is used as an email marketing service. This subdomain is not officially registered by the Coca-Cola company and does not have proper DNS records. This can be used by irresponsible parties to carry out subdomain takeover attacks. Therefore, the Coca-Cola company needs to take more proactive steps to improve subdomain settings and avoid subdomain takeover attacks.

### Impact

Subdomain takeover attacks can compromise the security of enterprise systems and data. The party carrying out the attack can take control of the subdomain and manipulate the data sent through the subdomain. The impact of this attack can impact a company's reputation and even cause financial loss if sensitive data such as user information or access credentials is compromised or compromised.

In the case of the `link.coca-cola.com` subdomain that points to the sendgrid.net service, a potential subdomain takeover attack could result in email abuse and threaten the security of user data, including access credentials and personal data.

Financial losses are also possible if unauthorized parties send phishing or spam emails through the subdomain, which can result in customers losing trust in the company and avoiding using its products or services.

Therefore, it is important to ensure that unused or expired subdomains are not misused to avoid subdomain takeover attacks and protect company data and systems.

### Recommendation

To prevent subdomain takeover attacks, companies need to exercise proper subdomain management, including:
- Monitor unused and expired subdomains regularly, and remove them when not needed
- Avoid using CNAME subdomains for unrecognized or trusted third party services.
- Assign unique and unpredictable subdomains to reduce the risk of subdomain takeover attacks.
- Implement secure DNS configuration for subdomains and enable DNSSEC to improve DNS integrity and security.

It is important to maintain the security of company systems and data by being aware of potential subdomain takeover attacks and taking the necessary precautions. Thus, companies can protect their reputation and customer trust, and prevent financial losses caused by such attacks.
### Conclusion

The conclusion of this report is to provide a deeper understanding of potential subdomain takeover attacks on the subdomain link.coca-cola.com connected to the email marketing service sendgrid.net, and to provide appropriate recommendations to prevent such attacks from occurring. This report is expected to help security professionals and enterprises better understand the security risks associated with subdomain takeover attacks, and be able to take effective measures to protect corporate systems and data.

### Closing

From the research results, it can be concluded that the takeover subdomain on the link.coca-cola.com subdomain can threaten the security of the company's systems and data which can be caused by negligence in subdomain configuration and settings. Therefore, proper precautions are required such as updating DNS configurations and deleting unused or incorrectly registered subdomains.

It is hoped that the recommendations provided in this report will help enterprises and security professionals to raise awareness about subdomain takeover attacks and implement appropriate countermeasures to address security risks resulting from such attacks.

In conclusion, this study demonstrates the importance of effective management of subdomains and implementation of appropriate countermeasures to reduce the risk of subdomain takeover attacks on enterprise systems and data.

### Bibliography

- [Barker, J. (2019). Subdomain Takeover Vulnerability Explained. The Hacker News.](https://thehackernews.com/2019/05/subdomain-takeover-vulnerability.html)
- [Chen, H., Hu, X., Yang, W., & Huang, X. (2020). Subdomain takeover attacks: Analysis, detection and defense. Journal of Network and Computer Applications, 152, 102547.](https://doi.org/10.1016/j.jnca.2020.102547)
- [Dogan, F., & Akgun, M. 2021. An analysis of subdomain takeover vulnerabilities and their detection methods. Journal of Cybersecurity, 7(1), tyab002.](https://doi.org/10.1093/cybsec/tyab002)
- [Shaw, D., & Jordan, M. 2019. What is a subdomain takeover and why does it matter? Cloudbric.](https://www.cloudbric.com/blog/2019/08/what-is-a-subdomain-takeover-and-why-does-it-matter/)
- [OWASP 2021 Subdomain takeover.](https://owasp.org/www-community/attacks/Subdomain_takeover)
- [SendGrid 2021.](https://sendgrid.com/)
