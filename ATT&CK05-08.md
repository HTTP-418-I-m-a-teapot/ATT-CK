# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

***

<!-- TOC -->autoauto- [[**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)](#mitre-attck-enterprise-frameworkhttpsattackmitreorg)auto    - [Perface](#perface)auto    - [Initial Access (初始入侵)](#initial-access-初始入侵)auto        - [[Drive-by Compromise](https://attack.mitre.org/techniques/T1189/) (过路式入侵)](#drive-by-compromisehttpsattackmitreorgtechniquest1189-过路式入侵)auto            - [0x00 背景](#0x00-背景)auto            - [0x01 利用](#0x01-利用)auto            - [0x02 探测](#0x02-探测)auto            - [0x03 缓解](#0x03-缓解)auto        - [Exploit Public-Facing Application (利用大众化应用程序)](#exploit-public-facing-application-利用大众化应用程序)auto            - [0x00 背景](#0x00-背景-1)auto            - [0x01 利用](#0x01-利用-1)auto            - [0x02 检测](#0x02-检测)auto            - [0x03 缓解](#0x03-缓解-1)auto        - [External Remote Services (远程服务)](#external-remote-services-远程服务)auto        - [Hardware Additions](#hardware-additions)auto        - [Replication Through Removable Media (通过便携式媒介复制)](#replication-through-removable-media-通过便携式媒介复制)auto        - [Spearphishing Attachment (鱼叉式附件)](#spearphishing-attachment-鱼叉式附件)auto        - [Spearphishing Link (鱼叉式链接)](#spearphishing-link-鱼叉式链接)auto        - [Spearphishing via Service](#spearphishing-via-service)auto        - [Supply Chain Compromise](#supply-chain-compromise)auto        - [Trusted Relationship (信任关系)](#trusted-relationship-信任关系)auto        - [Valid Accounts (有效账号)](#valid-accounts-有效账号)auto    - [Execution](#execution)auto    - [Persistence](#persistence)auto    - [Privilege Escalation](#privilege-escalation)auto    - [Defense Evasion (防御规避)](#defense-evasion-防御规避)auto        - [[Access Token Manipulation](https://attack.mitre.org/techniques/T1134/) (访问令牌操纵) (Windows)](#access-token-manipulationhttpsattackmitreorgtechniquest1134-访问令牌操纵-windows)auto        - [[Binary Padding](https://attack.mitre.org/techniques/T1009/) (二进制填充) (all)](#binary-paddinghttpsattackmitreorgtechniquest1009-二进制填充-all)auto            - [0x00 背景](#0x00-背景-2)auto            - [0x01 利用](#0x01-利用-2)auto            - [0x02 检测](#0x02-检测-1)auto            - [0x03 缓解](#0x03-缓解-2)auto        - [[BITS Jobs](https://attack.mitre.org/techniques/T1197/) (BITS(Windows后台智能传输服务)利用) (Windows)](#bits-jobshttpsattackmitreorgtechniquest1197-bitswindows后台智能传输服务利用-windows)auto            - [0x00 背景](#0x00-背景-3)auto            - [0x01 利用](#0x01-利用-3)auto            - [0x02 检测](#0x02-检测-2)auto            - [0x03 缓解](#0x03-缓解-3)auto        - [Bypass User Account Control (UAC(用户账户控制)绕过) (Windows)](#bypass-user-account-control-uac用户账户控制绕过-windows)auto            - [内容同Privilege Escalation](#内容同privilege-escalation)auto            - [0x04 原文链接](#0x04-原文链接)auto        - [Clear Command History (清除命令历史记录) (Linux&MacOS)](#clear-command-history-清除命令历史记录-linuxmacos)auto            - [0x00 背景](#0x00-背景-4)auto            - [0x01 利用](#0x01-利用-4)auto            - [0x02 检测](#0x02-检测-3)auto            - [0x03 缓解](#0x03-缓解-4)auto            - [0x04 原文链接](#0x04-原文链接-1)auto        - [CMSTP](#cmstp)auto            - [0x00 背景](#0x00-背景-5)auto            - [0x01 利用](#0x01-利用-5)auto            - [0x02 检测](#0x02-检测-4)auto            - [0x03 缓解](#0x03-缓解-5)auto            - [0x04 原文链接](#0x04-原文链接-2)auto        - [Code Signing](#code-signing)auto        - [Compile After Delivery](#compile-after-delivery)auto        - [Compiled HTML File](#compiled-html-file)auto        - [Component Firmware](#component-firmware)auto        - [Component Object Model Hijacking](#component-object-model-hijacking)auto        - [Connection Proxy](#connection-proxy)auto        - [Control Panel Items](#control-panel-items)auto        - [DCShadow](#dcshadow)auto        - [Deobfuscate/Decode Files or Information](#deobfuscatedecode-files-or-information)auto        - [Disabling Security Tools](#disabling-security-tools)auto        - [DLL Search Order Hijacking](#dll-search-order-hijacking)auto        - [DLL Side-Loading](#dll-side-loading)auto        - [Execution Guardrails](#execution-guardrails)auto        - [Exploitation for Defense Evasion](#exploitation-for-defense-evasion)auto        - [Extra Window Memory Injection](#extra-window-memory-injection)auto        - [File and Directory Permissions Modification](#file-and-directory-permissions-modification)auto        - [File Deletion](#file-deletion)auto        - [File System Logical Offsets](#file-system-logical-offsets)auto        - [Gatekeeper Bypass](#gatekeeper-bypass)auto        - [Group Policy Modification](#group-policy-modification)auto        - [Hidden Files and Directories](#hidden-files-and-directories)auto        - [Hidden Users](#hidden-users)auto        - [Hidden Window](#hidden-window)auto        - [HISTCONTROL](#histcontrol)auto        - [Image File Execution Options Injection](#image-file-execution-options-injection)auto        - [Indicator Blocking](#indicator-blocking)auto        - [Indicator Removal from Tools](#indicator-removal-from-tools)auto        - [Indicator Removal on Host](#indicator-removal-on-host)auto        - [Indirect Command Execution](#indirect-command-execution)auto        - [Install Root Certificate](#install-root-certificate)auto        - [InstallUtil](#installutil)auto        - [Launchctl](#launchctl)auto        - [LC_MAIN Hijacking](#lc_main-hijacking)auto        - [Masquerading](#masquerading)auto        - [Modify Registry](#modify-registry)auto        - [Mshta](#mshta)auto        - [Network Share](#network-share)auto        - [Connection Removal](#connection-removal)auto        - [NTFS File Attributes](#ntfs-file-attributes)auto        - [Obfuscated Files or Information](#obfuscated-files-or-information)auto        - [Parent PID Spoofing](#parent-pid-spoofing)auto        - [Plist Modification](#plist-modification)auto        - [Port Knocking](#port-knocking)auto        - [Process Doppelgänging](#process-doppelgänging)auto        - [Process Hollowing](#process-hollowing)auto        - [Process Injection](#process-injection)auto        - [Redundant Access](#redundant-access)auto        - [Regsvcs/Regasm](#regsvcsregasm)auto        - [Regsvr32](#regsvr32)auto        - [Rootkit](#rootkit)auto        - [Rundll32](#rundll32)auto        - [Scripting](#scripting)auto        - [Signed Binary Proxy Execution](#signed-binary-proxy-execution)auto        - [Signed Script Proxy Execution](#signed-script-proxy-execution)auto        - [SIP and Trust Provider Hijacking](#sip-and-trust-provider-hijacking)auto        - [Software Packing](#software-packing)auto        - [Space after Filename](#space-after-filename)auto        - [Template Injectio](#template-injectio)auto        - [Timestomp](#timestomp)auto        - [Trusted Developer Utilities](#trusted-developer-utilities)auto        - [Valid Accounts](#valid-accounts)auto        - [Virtualization/Sandbox Evasion](#virtualizationsandbox-evasion)auto        - [Web Service](#web-service)auto        - [XSL Script Processing](#xsl-script-processing)auto    - [Credential Access (凭证访问)](#credential-access-凭证访问)auto        - [Account Manipulation](#account-manipulation)auto        - [Bash History](#bash-history)auto        - [Brute Force](#brute-force)auto        - [Credential Dumping](#credential-dumping)auto        - [Credentials from Web Browsers](#credentials-from-web-browsers)auto        - [Credentials in Files](#credentials-in-files)auto        - [Credentials in Registry](#credentials-in-registry)auto        - [Exploitation for Credential Access](#exploitation-for-credential-access)auto        - [Forced Authentication](#forced-authentication)auto        - [Hooking](#hooking)auto        - [Input Capture](#input-capture)auto        - [Input Prompt](#input-prompt)auto        - [Kerberoasting](#kerberoasting)auto        - [Keychain](#keychain)auto        - [LLMNR/NBT-NS Poisoning and Relay](#llmnrnbt-ns-poisoning-and-relay)auto        - [Network Sniffing](#network-sniffing)auto        - [Password Filter DLL](#password-filter-dll)auto        - [Private Keys](#private-keys)auto        - [Securityd Memory](#securityd-memory)auto        - [Steal Web Session Cookie](#steal-web-session-cookie)auto        - [Two-Factor Authentication Interception](#two-factor-authentication-interception)auto    - [Discovery (嗅探扫描)](#discovery-嗅探扫描)auto        - [Account Discovery](#account-discovery)auto        - [Application Window Discovery](#application-window-discovery)auto        - [Browser Bookmark Discovery](#browser-bookmark-discovery)auto        - [Domain Trust Discovery](#domain-trust-discovery)auto        - [File and Directory Discovery](#file-and-directory-discovery)auto        - [Network Service Scanning](#network-service-scanning)auto        - [Network Share Discovery](#network-share-discovery)auto        - [Network Sniffing](#network-sniffing-1)auto        - [Password Policy Discovery](#password-policy-discovery)auto        - [Peripheral Device Discovery](#peripheral-device-discovery)auto        - [Permission Groups Discovery](#permission-groups-discovery)auto        - [Process Discovery](#process-discovery)auto        - [Query Registry](#query-registry)auto        - [Remote System Discovery](#remote-system-discovery)auto        - [Security Software Discovery](#security-software-discovery)auto        - [Software Discovery](#software-discovery)auto        - [System Information Discovery](#system-information-discovery)auto        - [System Network Configuration Discovery](#system-network-configuration-discovery)auto        - [System Network Connections Discovery](#system-network-connections-discovery)auto        - [System Owner/User Discovery](#system-owneruser-discovery)auto        - [System Service Discovery](#system-service-discovery)auto        - [System Time Discovery](#system-time-discovery)auto        - [Virtualization/Sandbox Evasion](#virtualizationsandbox-evasion-1)auto    - [Lateral Movement(横向移动）](#lateral-movement横向移动)auto        - [AppleScript](#applescript)auto        - [Application Access Token](#application-access-token)auto        - [Application Deployment Software](#application-deployment-software)auto        - [Component Object Model and Distributed COM](#component-object-model-and-distributed-com)auto        - [Exploitation of Remote Services](#exploitation-of-remote-services)auto        - [Internal Spearphishing](#internal-spearphishing)auto        - [Logon Scripts](#logon-scripts)auto        - [Pass the Hash](#pass-the-hash)auto        - [Pass the Ticket](#pass-the-ticket)auto        - [Remote Desktop Protocol](#remote-desktop-protocol)auto        - [Remote File Copy](#remote-file-copy)auto        - [Remote Services](#remote-services)auto        - [Replication Through Removable Media](#replication-through-removable-media)auto        - [Shared Webroot](#shared-webroot)auto        - [SSH Hijacking](#ssh-hijacking)auto        - [Taint Shared Content](#taint-shared-content)auto        - [Third-party Software](#third-party-software)auto        - [Web Session Cookie](#web-session-cookie)auto        - [Windows Admin Shares](#windows-admin-shares)auto        - [Windows Remote Management](#windows-remote-management)auto    - [Collection](#collection)auto    - [Command and Control](#command-and-control)auto    - [Exfiltration](#exfiltration)auto    - [Impact](#impact)autoauto<!-- /TOC -->

***

## Perface

基于**MITRE ATT&CK模型**整理的文档式中译版。

建议针对**关键词语**采用双语对照，可以参照[**Initial Access**](#initial-access-%e5%88%9d%e5%a7%8b%e8%ae%bf%e9%97%ae)。

***

## Initial Access (初始入侵)

>攻击者正试图进入您的网络。

**初始访问** 包括使用 **各种入口向量** 在网络中获得其 **初始入侵点** 的技术。用于获取 **入侵点** 技术包括 **针对性的鱼叉攻击** 和 **公共Web服务器** 。通过 **初始访问** 获得的 **入侵点** 可能支持进一步侵入，例如 **有效的帐户群** 和 **远程服务的外部使用权** ，也可能由于密码的修改而失效。

### [Drive-by Compromise](https://attack.mitre.org/techniques/T1189/) (过路式入侵)

#### 0x00 背景

**过路式入侵** 是指攻击者通过用户在正常浏览过程中访问网站来获得对系统的访问权限。使用此技术，通常会将用户的Web浏览器作为攻击目标，但攻击者也可能会将受侵害的网站用于非利用行为，例如获取应用程序访问令牌。

存在多种将漏洞利用代码传递给浏览器的方法，包括：

- 恶意代码的注入
- 恶意广告的投放
- 内置的Web内容 (论坛帖子、评论等等)

对手使用的网站通常是特定社区(例如政府，特定行业或地区)访问的网站，其目标是基于共同利益来威胁特定用户或一组用户。这种有针对性的攻击被称为战略性网络入侵或水坑攻击。

#### 0x01 利用

- 用户访问了托管了攻击者受控内容的网站
- 脚本会自动执行，通常会搜索存在漏洞的浏览器或插件版本
  - 可能要求用户通过启用脚本或活动的网站组件并忽略警告对话框来协助此过程
- 一旦发现有漏洞的版本，攻击代码将会传到浏览器
- 如果利用成功，那么除非有其他保护措施，否则它将使对手代码在用户的系统上执行
  - 在某些情况下，在提供漏洞利用代码之前，需要在初始扫描后再次访问网站
  
#### 0x02 探测

- 防火墙和代理可以检查URL中潜在的已知危险域或参数
- 网络入侵检测系统，有时配合SSL/TLS MITM检测，可以查找已知的恶意脚本
- 合法网站的 **过路式入侵** 检测会很困难，还要寻找终端所提供的成功入侵的证据

#### 0x03 缓解

- 应用隔离与沙箱机制
- 漏洞利用防护
- 限制来自Web的内容
- 保持更新

### Exploit Public-Facing Application (利用大众化应用程序)

#### 0x00 背景

#### 0x01 利用

#### 0x02 检测

#### 0x03 缓解

### External Remote Services (远程服务)

### Hardware Additions

### Replication Through Removable Media (通过便携式媒介复制)

### Spearphishing Attachment (鱼叉式附件)

### Spearphishing Link (鱼叉式链接)

### Spearphishing via Service

### Supply Chain Compromise

### Trusted Relationship (信任关系)

### Valid Accounts (有效账号)

***

## Execution

***

## Persistence

***

## Privilege Escalation

***

## Defense Evasion (防御规避)

### [Access Token Manipulation](https://attack.mitre.org/techniques/T1134/) (访问令牌操纵) (Windows)

内容同Privilege Escalation
***

### [Binary Padding](https://attack.mitre.org/techniques/T1009/) (二进制填充) (all)

#### 0x00 背景

- 在不影响恶意软件功能和行为的前提下，使用二进制填充添加脏数据(junk data)并更改其在磁盘上的表现形式

- 填充部分通常由制造脏数据的函数生成，附加在末尾或恶意程序各个部分

#### 0x01 利用

- 改变文件散列，用以绕过基于哈希(hash-based)的工具的检测/防御机制
- 改变文件大小，用以绕过不为大文件提供检测服务工具的机制（如VirusTotal），并减少了文件被收集分析的可能性

#### 0x02 检测

- 在扫描和基于访问(on-access based)的检测工具中，引入基于文件的签名(file-based signature)技术

#### 0x03 缓解

- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解
  
***

### [BITS Jobs](https://attack.mitre.org/techniques/T1197/) (BITS(Windows后台智能传输服务)利用) (Windows)

#### 0x00 背景

+ Windows后台智能传输服务（BITS）是一种通过组件对象模型（COM）公开的一种低带宽异步文件传输机制，通常由更新程序、messengers服务和其他使用空闲带宽，并在后台运行而不中断其他联网应用的程序使用.
+ Microsoft提供了一个名为“ bitsadmin ” 的二进制文件和PowerShell cmdlet，用于创建和管理文件传输.

#### 0x01 利用

- 使用BITS在运行恶意代码后进行下载、执行、清理等危险操作
- 使用BITS通过创建长期作业(>90D)或在作业完成/出错或设备重启时调用任意程序，实现持久化
> 一个案例：[https://www.cnblogs.com/xiaozi/p/11833583.html](https://www.cnblogs.com/xiaozi/p/11833583.html)
- 使用BITS上传功能进行 Exfiltration Over Alternative Protocol （基于替代协议的渗透）.

#### 0x02 检测

- 在扫描和基于访问(on-access based)的检测工具中，引入基于文件的签名(file-based signature)技术

#### 0x03 缓解

- 流量过滤：修改安全设备策略，仅允许合法的BITS通信
- 系统配置：减少“组策略”中的默认BITS作业生存期，或通过编辑注册表HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS缩短 JobInactivityTimeout和MaxDownloadTime的值
- 访问控制：将BITS界面的访问权限限制为特定的用户或组

***

### [Bypass User Account Control](https://attack.mitre.org/techniques/T1088/) (UAC(用户账户控制)绕过) (Windows)

#### 内容同Privilege Escalation

***

### [Clear Command History](https://attack.mitre.org/techniques/T1088/) (清除命令历史记录) (Linux&MacOS)

#### 0x00 背景

- macOS和Linux都记录用户在终端terminal中键入的命令，通过"history"命令查看
- 登录后，在环境变量"HISTFILE"指向的文件中记录"HISTFILESIZE"大小的命令历史记录.用户注销时，信息刷新到主目录名为~/.bash_history的文件中.
- 保存了在命令行上键入的所有内容，因此也保存了在命令行上传递的密码

#### 0x01 利用

- 在"~/.bash_history"等文件中搜索明文密码.
- 阻止记录/删除攻击者键入的命令(unset HISTFILE，export HISTFILESIZE=0，history -c，rm ~/.bash_history).

#### 0x02 检测

- 用户身份验证后(尤其是通过SSH远程登录)，"~/.bash_history"中没有该用户的情况.
- 有修改"HISTFILE"和"HISTFILESIZE"环境变量，删除/清空"~/.bash_history"文件操作.

#### 0x03 缓解

- 环境变量配置：将关联"HISTFILE","HISTFILESIZE"的环境变量设置为只读，确保保留用户的命令历史记录.
- 文件访问控制：阻止用户删除或写入~/.bash_history.

***

### CMSTP

#### 0x00 背景

- 
- 

#### 0x01 利用

- 
- 
- 

#### 0x02 检测

- 

#### 0x03 缓解

- 
- 
- 

#### 0x04 原文链接

https://attack.mitre.org/techniques/T1088/
### Code Signing

### Compile After Delivery

### Compiled HTML File

### Component Firmware

### Component Object Model Hijacking

### Connection Proxy

### Control Panel Items

### DCShadow

### Deobfuscate/Decode Files or Information

### Disabling Security Tools

### DLL Search Order Hijacking

### DLL Side-Loading

### Execution Guardrails

### Exploitation for Defense Evasion

### Extra Window Memory Injection

### File and Directory Permissions Modification

### File Deletion

### File System Logical Offsets

### Gatekeeper Bypass

### Group Policy Modification

### Hidden Files and Directories

### Hidden Users

### Hidden Window

### HISTCONTROL

### Image File Execution Options Injection

### Indicator Blocking

### Indicator Removal from Tools	

### Indicator Removal on Host

### Indirect Command Execution

### Install Root Certificate

### InstallUtil

### Launchctl

### LC_MAIN Hijacking

### Masquerading

### Modify Registry

### Mshta

### Network Share

### Connection Removal

### NTFS File Attributes

### Obfuscated Files or Information

### Parent PID Spoofing	

### Plist Modification

### Port Knocking

### Process Doppelgänging

### Process Hollowing

### Process Injection

### Redundant Access

### Regsvcs/Regasm

### Regsvr32

### Rootkit

### Rundll32	

### Scripting

### Signed Binary Proxy Execution

### Signed Script Proxy Execution

### SIP and Trust Provider Hijacking

### Software Packing

### Space after Filename

### Template Injectio

### Timestomp

### Trusted Developer Utilities

### Valid Accounts

### Virtualization/Sandbox Evasion

### Web Service

### XSL Script Processing

***

## Credential Access (凭证访问)

### Account Manipulation

### Bash History

### Brute Force	

### Credential Dumping

### Credentials from Web Browsers

### Credentials in Files

### Credentials in Registry

### Exploitation for Credential Access

### Forced Authentication

### Hooking

### Input Capture

### Input Prompt

### Kerberoasting

### Keychain

### LLMNR/NBT-NS Poisoning and Relay

### Network Sniffing

### Password Filter DLL

### Private Keys

### Securityd Memory

### Steal Web Session Cookie

### Two-Factor Authentication Interception

***

## Discovery (嗅探扫描)

### Account Discovery

### Application Window Discovery

### Browser Bookmark Discovery

### Domain Trust Discovery

### File and Directory Discovery

### Network Service Scanning

### Network Share Discovery

### Network Sniffing

### Password Policy Discovery

### Peripheral Device Discovery

### Permission Groups Discovery

### Process Discovery

### Query Registry

### Remote System Discovery

### Security Software Discovery

### Software Discovery

### System Information Discovery

### System Network Configuration Discovery

### System Network Connections Discovery

### System Owner/User Discovery

### System Service Discovery

### System Time Discovery

### Virtualization/Sandbox Evasion

***

## Lateral Movement(横向移动）

### AppleScript

### Application Access Token

### Application Deployment Software

### Component Object Model and Distributed COM

### Exploitation of Remote Services

### Internal Spearphishing

### Logon Scripts

### Pass the Hash

### Pass the Ticket

### Remote Desktop Protocol

### Remote File Copy

### Remote Services

### Replication Through Removable Media

### Shared Webroot

### SSH Hijacking

### Taint Shared Content

### Third-party Software

### Web Session Cookie

### Windows Admin Shares

### Windows Remote Management

***

## Collection

***

## Command and Control

***

## Exfiltration

***

## Impact

***
