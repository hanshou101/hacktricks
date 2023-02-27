# Basic Forensic Methodology

<details>

<summary><strong><a href="https://www.twitch.tv/hacktricks_live/schedule">🎙️ HackTricks LIVE Twitch</a> Wednesdays 5.30pm (UTC) 🎙️ - <a href="https://www.youtube.com/@hacktricks_LIVE">🎥 Youtube 🎥</a></strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Creating and Mounting an Image


[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)


## Malware Analysis

This **isn't necessary the first step to perform once you have the image**. But you can use this malware analysis techniques independently if you have a file, a file-system image, memory image, pcap... so it's good to **keep these actions in mind**:


[malware-analysis.md](malware-analysis.md)


## Inspecting an Image

if you are given a **forensic image** of a device you can start **analyzing the partitions, file-system** used and **recovering** potentially **interesting files** (even deleted ones). Learn how in:


[partitions-file-systems-carving](partitions-file-systems-carving/)


Depending on the used OSs and even platform different interesting artifacts should be searched:


[windows-forensics](windows-forensics/)



[linux-forensics.md](linux-forensics.md)



[docker-forensics.md](docker-forensics.md)


## Deep inspection of specific file-types and Software

If you have very **suspicious** **file**, then **depending on the file-type and software** that created it several **tricks** may be useful.\
Read the following page to learn some interesting tricks:


[specific-software-file-type-tricks](specific-software-file-type-tricks/)


I want to do a special mention to the page:


[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)


## Memory Dump Inspection


[memory-dump-analysis](memory-dump-analysis/)


## Pcap Inspection


[pcap-inspection](pcap-inspection/)


## **Anti-Forensic Techniques**

Keep in mind the possible use of anti-forensic techniques:


[anti-forensic-techniques.md](anti-forensic-techniques.md)


## Threat Hunting


[file-integrity-monitoring.md](file-integrity-monitoring.md)


<details>

<summary><strong><a href="https://www.twitch.tv/hacktricks_live/schedule">🎙️ HackTricks LIVE Twitch</a> Wednesdays 5.30pm (UTC) 🎙️ - <a href="https://www.youtube.com/@hacktricks_LIVE">🎥 Youtube 🎥</a></strong></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
