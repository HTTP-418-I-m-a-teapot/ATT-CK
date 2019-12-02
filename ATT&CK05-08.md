# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

***



## Defense Evasion (防御规避)

>攻击者试图避免被发现。

**防御规避** 是指攻击者在**整条攻击链**中避免被发现的技术。包括**免杀**(uninstalling/disabling 卸载/瘫痪安全软件)和**加固**(obfuscating/encrypting 混淆/加密脚本和数据)，攻击者同样**武器化**利用受信任的进程来隐藏和伪装恶意软件。

***

### [Access Token Manipulation](https://attack.mitre.org/techniques/T1134/) (访问令牌操纵) (Windows)

内容同Privilege Escalation

***

## [Access Token Manipulation](https://attack.mitre.org/techniques/T1134/) (应用程序访问令牌) (SaaS&Office 365)

#### 0x00 背景

- 应用程序访问令牌用于代表用户发出授权的API请求，并且通常被作为在基于**云**的应用程序和软件即服务（**SaaS**）中访问资源的方式；
- 这些框架(如Oauth)可共同用于验证用户并确定用户被允许执行的操作。一旦建立了认证，令牌就可以授权操作，而无需传递用户的实际凭据；
- 攻击者可以使用应用程序访问令牌绕过传统的身份验证过程，并访问远程系统上的受限帐户、信息或服务，并作为**其他类型攻击的初始步骤**；
- 如果令牌授予受害者电子邮件的访问权限，则攻击者可能会通过触发忘记的密码，将访问权限扩展到目标用户订阅的所有其他服务。

#### 0x01 利用场景
- 以Oauth为例，如果后台访问的"更新令牌"被启用，一旦将OAuth访问令牌被恶意应用程序利用，，它有可能获得对用户帐户功能的**长期访问**；
- 通过令牌进行的直接API访问**不受第二个身份验证因素的影响**，并且可能不受诸如更改密码之类的直接策略的影响；
- 由于访问可以与合法的操作流程保持一致，因此即使从服务端也**难以检测**到通过API进行的访问滥用。

#### 0x02 检测
- **监视访问令牌活动**：管理员可以设置各种日志，并利用审核工具来监视令牌异常使用情况以及授予异常或可疑应用程序的权限。例如，审核报告使管理员能够识别特权升级操作，例如角色创建或策略修改等初次访问后执行的操作。

#### 0x03 缓解
- **日志审计**：监视令牌异常使用情况以及授予异常或可疑应用程序的权限;
- **信息加密**：在包含敏感信息传输的邮件通信中，强制实施加密;
- **Web限制**：更新策略，以限制将哪些类型的第三方应用程序添加到与公司的信息，帐户或网络链接的任何在线服务或工具。

***

### [Binary Padding](https://attack.mitre.org/techniques/T1009/) (二进制填充) (all)

#### 0x00 背景

- 在不影响恶意软件功能和行为的前提下，使用二进制填充添加脏数据(junk data)并更改其在磁盘上的表现形式；
- 填充部分通常由制造脏数据的函数生成，附加在末尾或恶意程序各个部分。

#### 0x01 利用场景

- 改变文件**散列**，用以绕过基于哈希(hash-based)的工具的检测/防御机制；
- 改变文件**大小**，用以绕过不为大文件提供检测服务工具的机制（如VirusTotal），并减少了文件被收集分析的可能性。

#### 0x02 检测

- 基于签名的检测中，引入基于访问(on-access based)的检测与扫描技术；
- 基于行为的检测中，横向移动等进行入侵的特征，可以作为指向源文件的标志。

#### 0x03 缓解

- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。
  
***

### [BITS Jobs](https://attack.mitre.org/techniques/T1197/) (BITS(Windows后台智能传输服务)利用) (Windows)

#### 0x00 背景

- Windows后台智能传输服务（BITS）是一种通过组件对象模型（COM）公开的一种低带宽异步文件传输机制，通常由更新程序、messengers服务和其他使用空闲带宽，并在后台运行而不中断其他联网应用的程序使用；
- Microsoft提供了一个名为“ bitsadmin ” 的二进制文件和“PowerShell cmdlet”，用于创建和管理文件传输。

#### 0x01 武器化

- 使用BITS在**运行恶意代码**后进行下载、执行、清理等危险操作；
- 使用BITS通过创建长期作业(>90D)或在作业完成/出错或设备重启时调用任意程序，实现**持久化**；
  > [一个案例](https://www.cnblogs.com/xiaozi/p/11833583.html)
- 使用BITS上传功能进行 **Exfiltration Over Alternative Protocol** （基于替代协议的渗透）。

#### 0x02 检测

- **运行状态**：
  - 使用SC查询程序 sc query bits 检查状态；
  - 使用BITSAdmin工具 bitsadmin /list /allusers /verbose 枚举活动的BITS任务。
- **使用情况**：
  - 监视BITSAdmin工具使用情况，关注‘Transfer’, 'Create', 'AddFile', 'SetNotifyFlags', 'SetNotifyCmdLine', 'SetMinRetryDelay', 'SetCustomHeaders','Resume'命令；
  - Admin与Windows事件日志中的BITS情况；
  - 分析BITS作业数据库信息。
- **网络活动**：
  - 使用HTTP(S)和SMB远程连接；
  - 与创建的用户绑定；
  - 用户登录后才启用（即使将作业附加到service账户)。

#### 0x03 缓解

- **流量过滤**：修改安全设备策略，仅允许合法的BITS通信；
- **系统配置**：减少“组策略”中的默认BITS作业生存期，或通过编辑注册表HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS 缩短 JobInactivityTimeout 和 MaxDownloadTime的值；
- **访问控制**：将BITS界面的访问权限限制为特定的用户或组。

***

### [Bypass User Account Control](https://attack.mitre.org/techniques/T1088/) (UAC(用户账户控制)绕过) (Windows)

#### 内容同Privilege Escalation

***

### [Clear Command History](https://attack.mitre.org/techniques/T1088/) (清除命令历史记录) (Linux&MacOS)

#### 0x00 背景

- macOS和Linux都记录用户在终端terminal中键入的命令，通过"history"命令查看；
- 登录后，在环境变量"HISTFILE"指向的文件中记录"HISTFILESIZE"大小的命令历史记录.用户注销时，信息刷新到主目录名为~/.bash_history的文件中；
- 保存了在命令行上键入的所有内容，因此也保存了在命令行上传递的密码。

#### 0x01 利用

- 在"~/.bash_history"等文件中**搜索**明文密码；
- **阻止记录/删除**攻击者键入的命令(unset HISTFILE，export HISTFILESIZE=0，history -c，rm ~/.bash_history)。

#### 0x02 检测

- 用户身份验证后(尤其是通过SSH远程登录)，"~/.bash_history"中没有该用户记录的情况；
- 有修改"HISTFILE"和"HISTFILESIZE"环境变量，删除/清空"~/.bash_history"文件操作。

#### 0x03 缓解

- **环境变量配置**：将关联"HISTFILE","HISTFILESIZE"的环境变量设置为只读，确保保留用户的命令历史记录；
- **文件访问控制**：阻止用户删除或写入~/.bash_history。

***

### [CMSTP](https://attack.mitre.org/techniques/T1191/)(CMSTP(Microsoft连接管理器配置文件安装程序)利用)(Windows)

#### 0x00 背景

- Microsoft连接管理器配置文件安装程序(CMSTP.exe)是用于安装连接管理器服务配置文件的命令行程序；
- CMSTP.exe接受安装信息文件（INF）作为参数，并安装用于远程访问连接的服务配置文件；
- 是经过签名的合法Microsoft应用程序。

#### 0x01 武器化

- 攻击者可能会向CMSTP.exe提供感染了**恶意命令**的INF文件；
- CMSTP.exe可能被滥用以从远程服务器**加载和执行**DLL和COM脚本(SCT)(与Regsvr32/ "Squiblydoo"相似)；
- 利用合法性和签名，该执行过程也可以**绕过**AppLocker和其他白名单防御；
- 绕过用户帐户控制，并通过自动提升(auto-elevated)的COM界面从恶意INF**执行**任意命令。
  > [一个案例](https://www.freebuf.com/articles/system/172515.html)

#### 0x02 检测

- **基于行为**：使用进程监视来检测和分析 CMSTP.exe 的执行情况和参数.将CMSTP.exe既往历史中最近调用与已知良好参数与加载文件的先前历史进行比较，以确定异常和潜在的对抗活动；
- **日志分析**：使用系统监视器通过检测策略，识别特定攻击程序对CMSTP.exe的潜在滥用。
  - 检测本地/远程负载加载执行：
    Event 1 (Process creation) :ParentImage 包含 CMSTP.exe
    Event 3 (Network connection) :Image 包含 CMSTP.exe 且源IP为外部IP
  - 检测利用自动提升的COM进程绕过UAC：
    Event 10 (ProcessAccess) :CallTrace 包含 CMLUA.dll
    Event 12 or 13 (RegistryEvent) :TargetObject 包含 CMMGR32.exe
    监视事件，如进程创建 (Sysmon Event 1), 涉及自动提升的 CMSTP COM 窗口 比如 CMSTPLUA (3E5FC7F9-9A51-4367-9063-A120244FBEC7) ，CMLUAUTIL (3E000D72-A845-4CD9-BD83-80C07C3B881F)

#### 0x03 缓解

- **功能禁用**：特定情况下（除VPN连接安装），CMSTP.exe 可能不是必需的；
- **预防执行**：为需要使用 CMSTP.exe 的应用程序创建白名单。

***

### [Code Signing](https://attack.mitre.org/techniques/T1116/)(代码签名)(MacOS&Windows)

### 0x00 背景
- 代码签名为开发人员提供的二进制文件提供了一定程度的真实性，并保证该二进制文件未被篡改；
- 攻击者会**创建、伪造和窃取**在操作过程中使用的证书，将恶意软件和工具伪装为合法二进制文件；
- 未在Linux使用。

### 0x01 利用
- 可用于**绕过**要求签名才能在系统上执行的安全策略。

### 0x02 检测
- 收集并分析在环境中执行的软件的签名证书元数据，以查找异常的证书特征和异常值。

### 0x03 缓解
- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。

***

### [Compile After Delivery](https://attack.mitre.org/techniques/T1500/)(交付后编译)(All)

### 0x00 背景
- 攻击者可能试图通过将文件作为**未编译的代码**交付给受害者；
- 有效载荷
  - 将需要在**执行之前进行编译**；
  - 也可以被**加密、编码和嵌入**在其他文件中；
  - 也可能以**无法识别的格式**传递给本机OS（例如，macOS / Linux上的exe），然后再通过捆绑的编译器和执行框架重编译为适当的可执行二进制文件。
  - 有效载荷的汇编可能**生成文件和创建文件写入事件**

### 0x01 利用
- 与模糊文件或信息(Obfuscated Files or Information)相似，基于文本的源代码文件可能会破坏针对可执行文件/二进制文件的保护措施的分析和审查。

### 0x02 检测
- **监视常见编译器**（例如csc.exe和GCC / MinGW）的执行文件路径和命令行参数，并与其他可疑行为相关联；
- **寻找非本机二进制格式以及跨平台的编译器和执行框架**（如Mono），并确定它们在系统上是否具有合法用途。
  
### 0x03 缓解
- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。

***

### [Compiled HTML File](https://attack.mitre.org/techniques/T1223/)(编译的HTML文件)(Windows)








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
