# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

***



## Defense Evasion (防御规避)

>攻击者试图避免被发现。

**防御规避** 是指攻击者在**整条攻击链**中避免被发现的技术。包括**免杀**(uninstalling/disabling 卸载/瘫痪安全软件)和**加固**(obfuscating/encrypting 混淆/加密脚本和数据)，攻击者同样**武器化**利用受信任的进程来隐藏和伪装恶意软件。

***

### Access Token Manipulation (访问令牌操纵) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1134/)

#### 背景
同上一部分特权升级



***

## Access Token Manipulation (应用程序访问令牌) (SaaS&Office 365)
>[原文链接](https://attack.mitre.org/techniques/T1527/)

#### 背景

- 应用程序访问令牌用于代表用户发出授权的API请求，并且通常被作为在基于**云**的应用程序和软件即服务（**SaaS**）中访问资源的方式；
- 这些框架(如Oauth)可共同用于验证用户并确定用户被允许执行的操作。一旦建立了认证，令牌就可以授权操作，而无需传递用户的实际凭据；
- 攻击者可以使用应用程序访问令牌绕过传统的身份验证过程，并访问远程系统上的受限帐户、信息或服务，并作为**其他类型攻击的初始步骤**；
- 如果令牌授予受害者电子邮件的访问权限，则攻击者可能会通过触发忘记的密码，将访问权限扩展到目标用户订阅的所有其他服务。

#### 利用场景
- 以Oauth为例，如果后台访问的"更新令牌"被启用，一旦将OAuth访问令牌被恶意应用程序利用，，它有可能获得对用户帐户功能的**长期访问**；
- 通过令牌进行的直接API访问**不受第二个身份验证因素的影响**，并且可能不受诸如更改密码之类的直接策略的影响；
- 由于访问可以与合法的操作流程保持一致，因此即使从服务端也**难以检测**到通过API进行的访问滥用。


#### 缓解
缓解|描述
:--:|:--
**日志审计**|监视令牌异常使用情况以及授予异常或可疑应用程序的权限;
**信息加密**|在包含敏感信息传输的邮件通信中，强制实施加密;
**Web内容限制**|更新策略，以限制将哪些类型的第三方应用程序添加到与公司的信息，帐户或网络链接的任何在线服务或工具。

#### 检测
- **监视访问令牌活动**：管理员可以设置各种日志，并利用审核工具来监视令牌异常使用情况以及授予异常或可疑应用程序的权限。例如，审核报告使管理员能够识别特权升级操作，例如角色创建或策略修改等初次访问后执行的操作。
***

### Binary Padding (二进制填充) (all)
>[原文链接](https://attack.mitre.org/techniques/T1009/)

#### 背景

- 在不影响恶意软件功能和行为的前提下，使用二进制填充添加脏数据(junk data)并更改其在磁盘上的表现形式；
- 填充部分通常由制造脏数据的函数生成，附加在末尾或恶意程序各个部分。

#### 利用场景

- 改变文件**散列**，用以绕过基于哈希(hash-based)的工具的检测/防御机制；
- 改变文件**大小**，用以绕过不为大文件提供检测服务工具的机制（如VirusTotal），并减少了文件被收集分析的可能性。

#### 缓解

- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。
 
#### 检测

- 基于签名的检测中，引入基于访问(on-access based)的检测与扫描技术；
- 基于行为的检测中，横向移动等进行入侵的特征，可以作为指向源文件的标志。 
***

### BITS Jobs (BITS-Windows后台智能传输服务-利用) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1197/)

#### 背景

- Windows后台智能传输服务（BITS）是一种通过组件对象模型（COM）公开的一种低带宽异步文件传输机制，通常由更新程序、messengers服务和其他使用空闲带宽，并在后台运行而不中断其他联网应用的程序使用；
- Microsoft提供了一个名为“ bitsadmin ” 的二进制文件和“PowerShell cmdlet”，用于创建和管理文件传输。

#### 武器化

- 使用BITS在**运行恶意代码**后进行下载、执行、清理等危险操作；
- 使用BITS通过创建长期作业(>90D)或在作业完成/出错或设备重启时调用任意程序，实现**持久化**；
  > [一个案例](https://www.cnblogs.com/xiaozi/p/11833583.html)
- 使用BITS上传功能进行 **Exfiltration Over Alternative Protocol** （基于替代协议的渗透）。

#### 缓解
缓解|描述
:--:|:--
**流量过滤**|修改安全设备策略，仅允许合法的BITS通信；
**系统配置**|减少“组策略”中的默认BITS作业生存期，或通过编辑注册表HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS 缩短 JobInactivityTimeout 和 MaxDownloadTime的值；
**访问控制**|将BITS界面的访问权限限制为特定的用户或组。

#### 检测

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

***

### Bypass User Account Control (UAC-用户账户控制-绕过) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1088/)

同上一部分特权升级

***

### Clear Command History (清除命令历史记录) (Linux&MacOS)
>[原文链接](https://attack.mitre.org/techniques/T1146/)

#### 背景

- macOS和Linux都记录用户在终端terminal中键入的命令，通过"history"命令查看；
- 登录后，在环境变量"HISTFILE"指向的文件中记录"HISTFILESIZE"大小的命令历史记录.用户注销时，信息刷新到主目录名为~/.bash_history的文件中；
- 保存了在命令行上键入的所有内容，因此也保存了在命令行上传递的密码。

#### 利用场景

- 在"~/.bash_history"等文件中**搜索**明文密码；
- **阻止记录/删除**攻击者键入的命令(unset HISTFILE，export HISTFILESIZE=0，history -c，rm ~/.bash_history)。

#### 缓解
缓解|描述
:--:|:--
**环境变量配置**|将关联"HISTFILE","HISTFILESIZE"的环境变量设置为只读，确保保留用户的命令历史记录；
**文件访问控制**|阻止用户删除或写入~/.bash_history。

#### 检测
- 基于行为
  - 用户身份验证后(尤其是通过SSH远程登录)，"~/.bash_history"中没有该用户记录的情况；
  - 有修改"HISTFILE"和"HISTFILESIZE"环境变量，删除/清空"~/.bash_history"文件操作。
***

### CMSTP (CMSTP-Microsoft连接管理器配置文件安装程序-利用) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1191/)


#### 背景

- Microsoft连接管理器配置文件安装程序(CMSTP.exe)是用于安装连接管理器服务配置文件的命令行程序；
- CMSTP.exe接受安装信息文件（INF）作为参数，并安装用于远程访问连接的服务配置文件；
- 是经过签名的合法Microsoft应用程序。

#### 武器化

- 攻击者可能会向CMSTP.exe提供感染了**恶意命令**的INF文件；
- CMSTP.exe可能被滥用以从远程服务器**加载和执行**DLL和COM脚本(SCT)(与Regsvr32/ "Squiblydoo"相似)；
- 利用合法性和签名，该执行过程也可以**绕过**AppLocker和其他白名单防御；
- 绕过用户帐户控制，并通过自动提升(auto-elevated)的COM界面从恶意INF**执行**任意命令。
  > [一个案例](https://www.freebuf.com/articles/system/172515.html)

#### 缓解
缓解|描述
:--:|:--
**功能禁用**|特定情况下（除VPN连接安装），CMSTP.exe 可能不是必需的；
**预防执行**|为需要使用 CMSTP.exe 的应用程序创建白名单。
#### 检测

- **基于行为**：使用进程监视来检测和分析 CMSTP.exe 的执行情况和参数.将CMSTP.exe既往历史中最近调用与已知良好参数与加载文件的先前历史进行比较，以确定异常和潜在的对抗活动；
- **日志分析**：使用系统监视器通过检测策略，识别特定攻击程序对CMSTP.exe的潜在滥用。
  - 检测本地/远程负载加载执行：
    Event 1 (Process creation) :ParentImage 包含 CMSTP.exe
    Event 3 (Network connection) :Image 包含 CMSTP.exe 且源IP为外部IP
  - 检测利用自动提升的COM进程绕过UAC：
    Event 10 (ProcessAccess) :CallTrace 包含 CMLUA.dll
    Event 12 or 13 (RegistryEvent) :TargetObject 包含 CMMGR32.exe
    监视事件，如进程创建 (Sysmon Event 1), 涉及自动提升的 CMSTP COM 窗口 比如 CMSTPLUA (3E5FC7F9-9A51-4367-9063-A120244FBEC7) ，CMLUAUTIL (3E000D72-A845-4CD9-BD83-80C07C3B881F)


***

### Code Signing (代码签名) (MacOS&Windows)
>[原文链接](https://attack.mitre.org/techniques/T1116/)

### 背景
- 代码签名为开发人员提供的二进制文件提供了一定程度的真实性，并保证该二进制文件未被篡改；
- 攻击者会**创建、伪造和窃取**在操作过程中使用的证书，将恶意软件和工具伪装为合法二进制文件；
- 未在Linux使用。

### 利用场景
- 可用于**绕过**要求**签名**才能在系统上执行的安全策略。

### 缓解
- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。
  
### 检测
- 收集并分析在环境中执行的软件的签名证书元数据，以查找异常的证书特征和异常值。


***

### Compile After Delivery (交付后编译) (All)
>[原文链接](https://attack.mitre.org/techniques/T1500/)

### 背景
- 攻击者可能试图通过将文件作为**未编译的代码**交付给受害者；
- 有效载荷
  - 将需要在**执行之前进行编译**；
  - 也可以被**加密、编码和嵌入**在其他文件中；
  - 也可能以**无法识别的格式**传递给本机OS（例如，macOS / Linux上的exe），然后再通过捆绑的编译器和执行框架重编译为适当的可执行二进制文件。
  - 有效载荷的汇编可能**生成文件和创建文件写入事件**

### 利用场景
- 与模糊文件或信息(Obfuscated Files or Information)相似，基于文本的源代码文件可能会破坏针对可执行文件/二进制文件的保护措施的分析和审查。
  
### 缓解
- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。
  
### 检测
- **监视常见编译器**（例如csc.exe和GCC / MinGW）的执行文件路径和命令行参数，并与其他可疑行为相关联；
- **寻找非本机二进制格式以及跨平台的编译器和执行框架**（如Mono），并确定它们在系统上是否具有合法用途。


***

### Compiled HTML File (编译的HTML文件) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1223/)

### 背景
- 编译的HTML文件，即 **.CHM**(Compiled Help Manual 已编译的帮助文件)，是微软新一代的帮助文件格式，利用HTML作源文，把帮助内容以类似数据库的形式编译储存。
- CHM文件是各种内容的压缩汇编，如HTML文档，图像以及与脚本/Web相关的编程语言(如VBA，JScript、Java、ActiveX)。
- 通常作为Microsoft HTML系统帮助的一部分分发。
- CHM内容使用HTML帮助可执行程序(**hh.exe**)加载的Internet Explorer浏览器的基础组件显示。

### 利用场景
- 攻击者可能会滥用该技术来**隐藏恶意代码**。包含嵌入式有效负载的自定义CHM文件可以传递给受害者，然后由User Execution触发。
- CHM执行还可以**绕过**没有考虑通过hh.exe执行二进制文件的，较旧和未打补丁的系统上的应用**白名单**。

## 缓解
缓解|描述
:--:|:--
**可执行程序白名单**|如果给定系统或网络不需要hh.exe，使用应用程序白名单来阻止hh.exe执行；
**web内容限制**|阻止下载/传输和执行可能在入侵过程中使用的罕见文件类型，例如.CHM文件。

## 检测
- **hh.exe**：监视和分析hh.exe的执行和参数。
  - 将hh.exe的最近调用与已知良好参数的先前历史进行比较，以确定异常和潜在的对抗活动（例混淆和恶意命令）。
  - 非标准进程执行树也可能表示可疑或恶意行为，如hh.exe是与其他对抗技术有关的可疑进程和活动的父进程。
- **CHM文件**：监视CHM文件的存在和使用，尤其是在环境中通常不使用它们的情况下。


***

### Component Firmware (组件固件) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1109/)

## 背景
- 一些攻击者可能会采用复杂的手段来破坏计算机组件并**安装恶意固件**，这些固件将在操作系统和主系统固件或BIOS之外执行攻击者代码。
- 该技术可能与系统固件System Firmware类似，但是可在不具有相同的完整性检查功能与级别的其他系统组件上执行。

## 武器化
- 可以提供对系统的**持久访问级别**，但可能会出现权限维持故障和硬盘重映像等问题。
- 可以提供逃避**基于软件的防御和完整性检查**方法。
  
## 缓解
- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。
  
## 检测
- **数据和遥测(Data and telemetry)技术**：通过设备驱动程序(进程与API)使用情况、SMART(自我监控、分析和报告技术)提供的磁盘监控提供的数据和遥测(**Data and telemetry**)，检测组件的恶意操作；但如果恶意活动发生在系统组件上，或超出操作系统安全性和完整性机制的权限，此技术可能难以检测。
- **磁盘检查与电子取证工具**：可能会显示恶意固件的迹象，例如字符串，意外的磁盘分区表条目或其他异常内存块。
- **与正常镜像对比**：将组件（包括组件固件和行为的哈希值）与已知的良好镜像进行比较。


***

### Component Object Model Hijacking (COM-组件对象模型-劫持) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1122/)

## 背景
- 组件对象模型（**COM**）是Windows中的一个系统，用于通过操作系统在软件组件之间进行交互。
- 劫持COM对象需要在Windows注册表中进行更改，以替换对合法系统组件的引用，这可能导致该组件在执行时不起作用。

## 利用场景
- 攻击者可以使用此系统来插入通过**劫持COM引用和关系**(references and relationships )作为**持久性**手段来代替合法软件，通过正常的系统操作执行该系统组件时，将改为执行攻击者的代码。
- 攻击者很可能会劫持**经常使用的对象**，以维持一致的持久性水平，但不太可能破坏系统内的显著功能，以避免系统不稳定导致异常检测。
  
## 缓解
- 属于基于系统特性的恶意使用，无法通过预防性控制简单缓解。
  
## 检测
- **注册表**：搜索已被替换的注册表引用，即通过注册表操作将已知二进制路径替换为未知路径来检测COM劫持。
  - 即使某些第三方应用程序定义了用户COM对象，如果用户的HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\对象在机器之前被加载，则该项中的对象有可能是可疑的，应该进行调查。
- **软件DLL负载**：检测与COM对象注册表修改相关的任何异常DLL负载。

***

### Connection Proxy (连接代理) (All)
>[原文链接](https://attack.mitre.org/techniques/T1090/)

## 背景
- 攻击者可以使用连接代理在系统之间定向网络流量，或者充当与命令与服务器进行网络通信的中介，以**避免直接连接**。
- 现有许多工具可以通过**代理**或**端口重定向**达到**流量重定向**，包括HTRAN，ZXProxy和ZXPortMap。

## 利用场景
- 攻击者使用这类代理来管理命令和控制通信，以**减少出站网络连接的数量**，在连接丢失时提供**弹性**(resiliency，即使其中一个或多个节点停止工作，整个系统也必须能继续运行)，**跨越**受害者之间现有的**可信通信路径**以避免怀疑。
- **外部连接代理**：
  - 用于**掩盖C2流量**(命令控制)的目的地，通常使用端口重定向实现。
  - 受害环境之外的脆弱系统以及已购买的基础架构（如基于云的资源或虚拟专用服务器）可能被作为pivot。
  - 基于对从受感染系统到代理的连接被调查的可能性小的原则选择代理。
  - 受害者系统将直接与Internet上的外部代理进行通信，然后该代理会将通信**转发**到C2服务器。
- **内部连接代理**:
  - 可用于**合并来自受感染系统的内部连接**。
  - 攻击者可能使用脆弱的内部系统作为代理，以**隐藏C2流量真实目的地**。
  - 代理可以将流量从网络内部的受感染系统重定向到外部C2服务器，从而**难以发现恶意流量**。
  - 另外，该网络可用于将信息从一个系统转发到另一个系统，以**避免流量广播**。
- **ssrf**

## 缓解
缓解|描述
:--:|:--
**网络入侵防御**|使用网络签名识别特定攻击者恶意软件流量的NIPS可用于减轻网络级别的活动。

## 检测
- **基于特征**:
  - 通常不进行网络通信的进程使用网络；
  - 陌生进程使用网络；
  - 通常需要用户操作的进程中，用户驱动与网络活动分离。
- **数据流分析**
  - 不常见的数据流行为(客户端发送数据远大于服务器接收的数据/不应频繁通信的服务频繁通信等)；
  - 通常不进行网络通信的进程使用网络；
  - 陌生进程使用网络；
- **数据包分析**：分析数据包内容，检测端口不遵循本应使用协议的通信行为。


## 补充
- 签名通常用于协议内的**唯一指示符**，并且可能由特定攻击者或工具使用的特定C2协议决定，在不同恶意软件系列和版本中可能不同。
- 攻击者可能会随着时间推移和协议构建**改变工具/C2的签名**，以避免被常见防御工具发现。
***

### Control Panel Items
>[原文链接](https://attack.mitre.org/techniques/T1196/)
同第二部分“执行”
## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### DCShadow DC(域控制器)阴影
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### Deobfuscate/Decode Files or Information
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### Disabling Security Tools
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### DLL Search Order Hijacking
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### DLL Side-Loading
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### Execution Guardrails
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### Exploitation for Defense Evasion
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### Extra Window Memory Injection
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### File and Directory Permissions Modification
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

### File Deletion
>[原文链接](https://attack.mitre.org/techniques/T/)

## 背景

## 利用场景

## 缓解
缓解|描述
:--:|:--

## 检测

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
