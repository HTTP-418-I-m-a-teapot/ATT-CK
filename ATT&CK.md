# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

***

<!-- TOC -->

- [**MITRE ATT&CK Enterprise FrameWork**](#mitre-attck-enterprise-framework)
  - [Perface](#perface)
  - [Initial Access (初始入侵)](#initial-access-%e5%88%9d%e5%a7%8b%e5%85%a5%e4%be%b5)
    - [Drive-by Compromise (过路式入侵)](#drive-by-compromise-%e8%bf%87%e8%b7%af%e5%bc%8f%e5%85%a5%e4%be%b5)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3)
    - [Exploit Public-Facing Application (利用大众化应用程序)](#exploit-public-facing-application-%e5%88%a9%e7%94%a8%e5%a4%a7%e4%bc%97%e5%8c%96%e5%ba%94%e7%94%a8%e7%a8%8b%e5%ba%8f)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af-1)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8-1)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b-1)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3-1)
    - [External Remote Services (外部远程服务)](#external-remote-services-%e5%a4%96%e9%83%a8%e8%bf%9c%e7%a8%8b%e6%9c%8d%e5%8a%a1)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af-2)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8-2)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b-2)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3-2)
    - [Hardware Additions](#hardware-additions)
    - [Replication Through Removable Media (通过便携式媒介复制)](#replication-through-removable-media-%e9%80%9a%e8%bf%87%e4%be%bf%e6%90%ba%e5%bc%8f%e5%aa%92%e4%bb%8b%e5%a4%8d%e5%88%b6)
    - [Spearphishing Attachment (鱼叉式附件)](#spearphishing-attachment-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%99%84%e4%bb%b6)
    - [Spearphishing Link (鱼叉式链接)](#spearphishing-link-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%93%be%e6%8e%a5)
    - [Spearphishing via Service](#spearphishing-via-service)
    - [Supply Chain Compromise](#supply-chain-compromise)
    - [Trusted Relationship (信任关系)](#trusted-relationship-%e4%bf%a1%e4%bb%bb%e5%85%b3%e7%b3%bb)
    - [Valid Accounts (有效账号)](#valid-accounts-%e6%9c%89%e6%95%88%e8%b4%a6%e5%8f%b7)
  - [Execution](#execution)
  - [Persistence](#persistence)
  - [Privilege Escalation](#privilege-escalation)
  - [Defense Evasion (防御规避)](#defense-evasion-%e9%98%b2%e5%be%a1%e8%a7%84%e9%81%bf)
    - [Access Token Manipulation (访问令牌操纵) (Windows)](#access-token-manipulation-%e8%ae%bf%e9%97%ae%e4%bb%a4%e7%89%8c%e6%93%8d%e7%ba%b5-windows)
    - [Binary Padding (二进制填充) (all)](#binary-padding-%e4%ba%8c%e8%bf%9b%e5%88%b6%e5%a1%ab%e5%85%85-all)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af-3)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8-3)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b-3)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3-3)
      - [0x04 原文链接](#0x04-%e5%8e%9f%e6%96%87%e9%93%be%e6%8e%a5)
    - [BITS Jobs (BITS(Windows后台智能传输服务)利用) (Windows)](#bits-jobs-bitswindows%e5%90%8e%e5%8f%b0%e6%99%ba%e8%83%bd%e4%bc%a0%e8%be%93%e6%9c%8d%e5%8a%a1%e5%88%a9%e7%94%a8-windows)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af-4)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8-4)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b-4)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3-4)
      - [0x04 原文链接](#0x04-%e5%8e%9f%e6%96%87%e9%93%be%e6%8e%a5-1)
    - [Bypass User Account Control (UAC(用户账户控制)绕过) (Windows)](#bypass-user-account-control-uac%e7%94%a8%e6%88%b7%e8%b4%a6%e6%88%b7%e6%8e%a7%e5%88%b6%e7%bb%95%e8%bf%87-windows)
      - [内容同Privilege Escalation](#%e5%86%85%e5%ae%b9%e5%90%8cprivilege-escalation)
      - [0x04 原文链接](#0x04-%e5%8e%9f%e6%96%87%e9%93%be%e6%8e%a5-2)
    - [Clear Command History (清除命令历史记录) (Linux&MacOS)](#clear-command-history-%e6%b8%85%e9%99%a4%e5%91%bd%e4%bb%a4%e5%8e%86%e5%8f%b2%e8%ae%b0%e5%bd%95-linuxmacos)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af-5)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8-5)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b-5)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3-5)
      - [0x04 原文链接](#0x04-%e5%8e%9f%e6%96%87%e9%93%be%e6%8e%a5-3)
    - [CMSTP](#cmstp)
      - [0x00 背景](#0x00-%e8%83%8c%e6%99%af-6)
      - [0x01 利用](#0x01-%e5%88%a9%e7%94%a8-6)
      - [0x02 检测](#0x02-%e6%a3%80%e6%b5%8b-6)
      - [0x03 缓解](#0x03-%e7%bc%93%e8%a7%a3-6)
      - [0x04 原文链接](#0x04-%e5%8e%9f%e6%96%87%e9%93%be%e6%8e%a5-4)
    - [Code Signing](#code-signing)
    - [Compile After Delivery](#compile-after-delivery)
    - [Compiled HTML File](#compiled-html-file)
    - [Component Firmware](#component-firmware)
    - [Component Object Model Hijacking](#component-object-model-hijacking)
    - [Connection Proxy](#connection-proxy)
    - [Control Panel Items](#control-panel-items)
    - [DCShadow](#dcshadow)
    - [Deobfuscate/Decode Files or Information](#deobfuscatedecode-files-or-information)
    - [Disabling Security Tools](#disabling-security-tools)
    - [DLL Search Order Hijacking](#dll-search-order-hijacking)
    - [DLL Side-Loading](#dll-side-loading)
    - [Execution Guardrails](#execution-guardrails)
    - [Exploitation for Defense Evasion](#exploitation-for-defense-evasion)
    - [Extra Window Memory Injection](#extra-window-memory-injection)
    - [File and Directory Permissions Modification](#file-and-directory-permissions-modification)
    - [File Deletion](#file-deletion)
    - [File System Logical Offsets](#file-system-logical-offsets)
    - [Gatekeeper Bypass](#gatekeeper-bypass)
    - [Group Policy Modification](#group-policy-modification)
    - [Hidden Files and Directories](#hidden-files-and-directories)
    - [Hidden Users](#hidden-users)
    - [Hidden Window](#hidden-window)
    - [HISTCONTROL](#histcontrol)
    - [Image File Execution Options Injection](#image-file-execution-options-injection)
    - [Indicator Blocking](#indicator-blocking)
    - [Indicator Removal from Tools](#indicator-removal-from-tools)
    - [Indicator Removal on Host](#indicator-removal-on-host)
    - [Indirect Command Execution](#indirect-command-execution)
    - [Install Root Certificate](#install-root-certificate)
    - [InstallUtil](#installutil)
    - [Launchctl](#launchctl)
    - [LC_MAIN Hijacking](#lcmain-hijacking)
    - [Masquerading](#masquerading)
    - [Modify Registry](#modify-registry)
    - [Mshta](#mshta)
    - [Network Share](#network-share)
    - [Connection Removal](#connection-removal)
    - [NTFS File Attributes](#ntfs-file-attributes)
    - [Obfuscated Files or Information](#obfuscated-files-or-information)
    - [Parent PID Spoofing](#parent-pid-spoofing)
    - [Plist Modification](#plist-modification)
    - [Port Knocking](#port-knocking)
    - [Process Doppelgänging](#process-doppelg%c3%a4nging)
    - [Process Hollowing](#process-hollowing)
    - [Process Injection](#process-injection)
    - [Redundant Access](#redundant-access)
    - [Regsvcs/Regasm](#regsvcsregasm)
    - [Regsvr32](#regsvr32)
    - [Rootkit](#rootkit)
    - [Rundll32](#rundll32)
    - [Scripting](#scripting)
    - [Signed Binary Proxy Execution](#signed-binary-proxy-execution)
    - [Signed Script Proxy Execution](#signed-script-proxy-execution)
    - [SIP and Trust Provider Hijacking](#sip-and-trust-provider-hijacking)
    - [Software Packing](#software-packing)
    - [Space after Filename](#space-after-filename)
    - [Template Injectio](#template-injectio)
    - [Timestomp](#timestomp)
    - [Trusted Developer Utilities](#trusted-developer-utilities)
    - [Valid Accounts](#valid-accounts)
    - [Virtualization/Sandbox Evasion](#virtualizationsandbox-evasion)
    - [Web Service](#web-service)
    - [XSL Script Processing](#xsl-script-processing)
  - [Credential Access (凭证访问)](#credential-access-%e5%87%ad%e8%af%81%e8%ae%bf%e9%97%ae)
    - [Account Manipulation](#account-manipulation)
    - [Bash History](#bash-history)
    - [Brute Force](#brute-force)
    - [Credential Dumping](#credential-dumping)
    - [Credentials from Web Browsers](#credentials-from-web-browsers)
    - [Credentials in Files](#credentials-in-files)
    - [Credentials in Registry](#credentials-in-registry)
    - [Exploitation for Credential Access](#exploitation-for-credential-access)
    - [Forced Authentication](#forced-authentication)
    - [Hooking](#hooking)
    - [Input Capture](#input-capture)
    - [Input Prompt](#input-prompt)
    - [Kerberoasting](#kerberoasting)
    - [Keychain](#keychain)
    - [LLMNR/NBT-NS Poisoning and Relay](#llmnrnbt-ns-poisoning-and-relay)
    - [Network Sniffing](#network-sniffing)
    - [Password Filter DLL](#password-filter-dll)
    - [Private Keys](#private-keys)
    - [Securityd Memory](#securityd-memory)
    - [Steal Web Session Cookie](#steal-web-session-cookie)
    - [Two-Factor Authentication Interception](#two-factor-authentication-interception)
  - [Discovery (嗅探扫描)](#discovery-%e5%97%85%e6%8e%a2%e6%89%ab%e6%8f%8f)
    - [Account Discovery](#account-discovery)
    - [Application Window Discovery](#application-window-discovery)
    - [Browser Bookmark Discovery](#browser-bookmark-discovery)
    - [Domain Trust Discovery](#domain-trust-discovery)
    - [File and Directory Discovery](#file-and-directory-discovery)
    - [Network Service Scanning](#network-service-scanning)
    - [Network Share Discovery](#network-share-discovery)
    - [Network Sniffing](#network-sniffing-1)
    - [Password Policy Discovery](#password-policy-discovery)
    - [Peripheral Device Discovery](#peripheral-device-discovery)
    - [Permission Groups Discovery](#permission-groups-discovery)
    - [Process Discovery](#process-discovery)
    - [Query Registry](#query-registry)
    - [Remote System Discovery](#remote-system-discovery)
    - [Security Software Discovery](#security-software-discovery)
    - [Software Discovery](#software-discovery)
    - [System Information Discovery](#system-information-discovery)
    - [System Network Configuration Discovery](#system-network-configuration-discovery)
    - [System Network Connections Discovery](#system-network-connections-discovery)
    - [System Owner/User Discovery](#system-owneruser-discovery)
    - [System Service Discovery](#system-service-discovery)
    - [System Time Discovery](#system-time-discovery)
    - [Virtualization/Sandbox Evasion](#virtualizationsandbox-evasion-1)
  - [Lateral Movement(横向移动）](#lateral-movement%e6%a8%aa%e5%90%91%e7%a7%bb%e5%8a%a8)
    - [AppleScript](#applescript)
    - [Application Access Token](#application-access-token)
    - [Application Deployment Software](#application-deployment-software)
    - [Component Object Model and Distributed COM](#component-object-model-and-distributed-com)
    - [Exploitation of Remote Services](#exploitation-of-remote-services)
    - [Internal Spearphishing](#internal-spearphishing)
    - [Logon Scripts](#logon-scripts)
    - [Pass the Hash](#pass-the-hash)
    - [Pass the Ticket](#pass-the-ticket)
    - [Remote Desktop Protocol](#remote-desktop-protocol)
    - [Remote File Copy](#remote-file-copy)
    - [Remote Services](#remote-services)
    - [Replication Through Removable Media](#replication-through-removable-media)
    - [Shared Webroot](#shared-webroot)
    - [SSH Hijacking](#ssh-hijacking)
    - [Taint Shared Content](#taint-shared-content)
    - [Third-party Software](#third-party-software)
    - [Web Session Cookie](#web-session-cookie)
    - [Windows Admin Shares](#windows-admin-shares)
    - [Windows Remote Management](#windows-remote-management)
  - [Collection](#collection)
  - [Command and Control](#command-and-control)
  - [Exfiltration](#exfiltration)
  - [Impact](#impact)

<!-- /TOC -->

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
  
#### 0x02 检测

- 防火墙和代理可以检查URL中潜在的已知危险域或参数
- 网络入侵检测系统，有时配合SSL/TLS MITM检测，可以查找已知的恶意脚本
- 合法网站的 **过路式入侵** 检测会很困难，还要寻找终端所提供的成功入侵的证据

#### 0x03 缓解

- 应用隔离与沙箱机制
- Exp防护
- 限制来自Web的内容
- 保持更新

### Exploit Public-Facing Application (利用大众化应用程序)

#### 0x00 背景

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的脆弱点，从而导致意外或无法预期的行为。

#### 0x01 利用

- 系统的弱点可能是bug，故障或设计漏洞
- 这些应用程序通常是网站，但是可以包括数据库(例如SQL)，标准服务(例如SMB或SSH)以及具有Internet可访问开放套接字的任何其他应用程序
- 如果应用程序托管在基于云的基础架构上，利用这一点可能会导致底层受到损害。这可以让攻击者获得访问云API或利用弱身份和访问管理策略

#### 0x02 检测

- 监视应用程序日志中是否有异常行为
- DPI检测
- WAF

#### 0x03 缓解

- 应用程序隔离和沙箱机制
- Exp防护
- 网络隔离
- 账户权限
- 软件更新
- 漏洞扫描

### External Remote Services (外部远程服务)

#### 0x00 背景

#### 0x01 利用

#### 0x02 检测

- 检测恶意使用有效账户对远程服务进行认证
- 收集身份验证日志并分析异常访问模式，以及正常工作时间之外的访问。

#### 0x03 缓解

- 禁用或阻止可能不必要的远程服务
- 限制通过网络对资源的访问
- 多因素认证
- 网络隔离

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

### Access Token Manipulation (访问令牌操纵) (Windows)

内容同Privilege Escalation
[官方链接](https://attack.mitre.org/techniques/T1134/)

### Binary Padding (二进制填充) (all)

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

#### 0x04 原文链接

[https://attack.mitre.org/techniques/T1009/](https://attack.mitre.org/techniques/T1009/)

### BITS Jobs (BITS(Windows后台智能传输服务)利用) (Windows)

#### 0x00 背景

- Windows后台智能传输服务（BITS）是一种通过组件对象模型（COM）公开的一种低带宽异步文件传输机制，通常由更新程序、messengers服务和其他使用空闲带宽，并在后台运行而不中断其他联网应用的程序使用.
- Microsoft提供了一个名为 **bitsadmin** 的二进制文件和PowerShell cmdlet，用于创建和管理文件传输.

#### 0x01 利用

- 使用BITS在运行恶意代码后进行下载、执行、清理等危险操作
- 使用BITS通过创建长期作业(>90D)或在作业完成/出错或设备重启时调用任意程序，实现持久化

一个案例：https://www.cnblogs.com/xiaozi/p/11833583.html

- 使用BITS在运行恶意代码后进行下载、执行、清理等危险操作.
- 使用BITS通过创建长期作业(>90D)或在作业完成/出错或设备重启时调用任意程序，实现持久化
  
一个案例：https://www.cnblogs.com/xiaozi/p/11833583.html

- 使用BITS上传功能进行 Exfiltration Over Alternative Protocol （基于替代协议的渗透）

#### 0x02 检测

- 在扫描和基于访问(on-access based)的检测工具中，引入基于文件的签名(file-based signature)技术.

#### 0x03 缓解

- 流量过滤：修改安全设备策略，仅允许合法的BITS通信.
- 系统配置：减少“组策略”中的默认BITS作业生存期，或通过编辑注册表HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS缩短 JobInactivityTimeout和MaxDownloadTime的值.
- 访问控制：将BITS界面的访问权限限制为特定的用户或组.

#### 0x04 原文链接

https://attack.mitre.org/techniques/T1197/

### Bypass User Account Control (UAC(用户账户控制)绕过) (Windows)

#### 内容同Privilege Escalation

#### 0x04 原文链接

https://attack.mitre.org/techniques/T1088/

### Clear Command History (清除命令历史记录) (Linux&MacOS)

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

#### 0x04 原文链接

https://attack.mitre.org/techniques/T1088/

### CMSTP

#### 0x00 背景

+ 
+ 

#### 0x01 利用

+ 
+ 
+ 

#### 0x02 检测

+ 

#### 0x03 缓解

+ 
+ 
+ 

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