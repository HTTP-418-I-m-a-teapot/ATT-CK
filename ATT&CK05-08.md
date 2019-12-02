# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

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
