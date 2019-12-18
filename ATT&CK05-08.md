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
同3 Privilege Escalation



***

## Application Access Token (应用程序访问令牌) (SaaS&Office 365)
>[原文链接](https://attack.mitre.org/techniques/T1527/)

同8 Lateral Movement
#### 背景

- 应用程序访问令牌用于代表用户发出授权的API请求，并且通常被作为在**云上应用**和**SaaS**(软件即服务)中访问资源的方式；
- 这些框架(如Oauth)可共同用于验证用户并确定用户被允许执行的操作。一旦建立了认证，令牌就可以授权操作，而无需传递用户的实际凭据；
- 攻击者可以使用应用程序访问令牌绕过传统的身份验证过程，并访问远程系统上的受限帐户、信息或服务，并作为**其他类型攻击的初始步骤**；
- 如果令牌授予受害者电子邮件的访问权限，则攻击者可能会通过触发忘记的密码，将访问权限扩展到目标用户订阅的所有其他服务。

#### 利用场景
- 以Oauth为例，如果后台访问的"更新令牌"功能启用，一旦将OAuth访问令牌被恶意程序利用，攻击者就有可能获得对用户帐户功能的**长期访问**；
- 通过令牌进行的直接API访问**不受第二个身份验证因素的影响**，并且可能绕过更改密码等策略的影响；
- 由于访问可以与合法的操作流程保持一致，因此即使从服务端也**难以检测**到通过API进行的访问滥用。


#### 防御方式
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

#### 防御方式

- 属于系统功能滥用，无法简单缓解。
 
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

#### 防御方式
缓解|描述
:--:|:--
**流量过滤**|修改安全设备策略，仅允许合法的BITS通信；
**系统配置**|减少“组策略”中的默认BITS作业生存期，或通过编辑注册表`HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS` 缩短 `JobInactivityTimeout` 和 `MaxDownloadTime` 的值；
**访问控制**|将BITS界面的访问权限限制为特定的用户或组。

#### 检测

- **运行状态**：
  - 使用SC查询程序`sc query bits`检查状态；
  - 使用BITSAdmin工具`bitsadmin /list /allusers /verbose`枚举活动的BITS任务。
- **使用情况**：
  - 监视BITSAdmin工具使用情况，关注`Transfer`、`Create`、`AddFile`、`SetNotifyFlags`、 `SetNotifyCmdLine`、`SetMinRetryDelay`、
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

- macOS和Linux都记录用户在终端terminal中键入的命令，通过`history`命令查看；
- 登录后，在环境变量`HISTFILE`指向的文件中记录`HISTFILESIZE`大小的命令历史记录.用户注销时，信息刷新到主目录名为 `~/.bash_history` 的文件中；
- 保存了在命令行上键入的所有内容，因此也保存了在命令行上传递的密码。

#### 利用场景

- 在`~/.bash_history`等文件中**搜索**明文密码；
- **阻止记录/删除**攻击者键入的命令(`unset HISTFILE`，`export HISTFILESIZE=0`，`history -c`，`rm ~/.bash_history`)。

#### 防御方式
缓解|描述
:--:|:--
**环境变量配置**|将关联`HISTFILE`,`HISTFILESIZE`的环境变量设置为只读，确保保留用户的命令历史记录；
**文件访问控制**|阻止用户删除或写入`~/.bash_history`。

#### 检测
- 基于行为
  - 用户身份验证后(尤其是通过SSH远程登录)，`~/.bash_history`中没有该用户记录的情况；
  - 有修改`HISTFILE`和`HISTFILESIZE`环境变量，删除/清空`~/.bash_history`文件操作。
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

#### 防御方式
缓解|描述
:--:|:--
**功能禁用**|特定情况下（除VPN连接安装），CMSTP.exe 可能不是必需的；
**预防执行**|为需要使用 CMSTP.exe 的应用程序创建白名单。
#### 检测

- **基于行为**：使用进程监视来检测和分析 CMSTP.exe 的执行情况和参数.将CMSTP.exe既往历史中最近调用与已知良好参数与加载文件的先前历史进行比较，以确定异常和潜在的对抗活动；
- **日志分析**：使用系统监视器通过检测策略，识别特定攻击程序对CMSTP.exe的潜在滥用。
  - 检测本地/远程负载加载执行：
    `Event 1 (Process creation) :ParentImage` 包含 CMSTP.exe
    `Event 3 (Network connection) :Image` 包含 CMSTP.exe 且源IP为外部IP
  - 检测利用自动提升的COM进程绕过UAC：
    `Event 10 (ProcessAccess) :CallTrace` 包含 CMLUA.dll
    `Event 12 or 13 (RegistryEvent) :TargetObject` 包含 CMMGR32.exe
    监视事件，如进程创建 (Sysmon Event 1), 涉及自动提升的 CMSTP COM 窗口 比如 `CMSTPLUA (3E5FC7F9-9A51-4367-9063-A120244FBEC7)` ，`CMLUAUTIL (3E000D72-A845-4CD9-BD83-80C07C3B881F)`


***

### Code Signing (代码签名) (MacOS&Windows)
>[原文链接](https://attack.mitre.org/techniques/T1116/)

### 背景
- 代码签名为开发人员提供的二进制文件提供了一定程度的真实性，并保证该二进制文件未被篡改；
- 攻击者会**创建、伪造和窃取**在操作过程中使用的证书，将恶意软件和工具伪装为合法二进制文件；
- 未在Linux使用。

### 利用场景
- 可用于**绕过**要求**签名**才能在系统上执行的安全策略。

### 防御方式
- 属于系统功能滥用，无法简单缓解。
  
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
  
### 防御方式
- 属于系统功能滥用，无法简单缓解。
  
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

## 防御方式
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
  
## 防御方式
- 属于系统功能滥用，无法简单缓解。
  
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
  
## 防御方式
- 属于系统功能滥用，无法简单缓解。
  
## 检测
- **注册表**：搜索已被替换的注册表引用，即通过注册表操作将已知二进制路径替换为未知路径来检测COM劫持。
  - 即使某些第三方应用程序定义了用户COM对象，如果用户的`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\`对象在机器之前被加载，则该项中的对象有可能是可疑的，应该进行调查。
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

## 防御方式
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


## 备注
- 签名通常用于协议内的**唯一指示符**，并且可能由特定攻击者或工具使用的特定C2协议决定，在不同恶意软件系列和版本中可能不同。
- 攻击者可能会随着时间推移和协议构建**改变工具/C2的签名**，以避免被常见防御工具发现。
***

### Control Panel Items
>[原文链接](https://attack.mitre.org/techniques/T1196/)

同第二部分“Executipn”

***
### DCShadow 影子DC(域控制器)
>[原文链接](https://attack.mitre.org/techniques/T1207/)

## 背景
- DCShadow是一种通过**注册**（或进行再次非活跃注册inactive registration）并**冒充**域控制器（DC）的行为来操作活动目录 Active Directory（AD）数据，包括对象和架构(objects and schemas)的方法。
  >[举个栗子](https://www.secpulse.com/archives/70892.html)
- 一旦注册成功，影子DC就可以为包括凭据和密钥在内的任何域对象进行**注入和更改**，并将其复制到AD基础结构中。
- 注册恶意DC需要在AD模式的配置`Configuration`中创建新服务器和`nTDSDSA`对象，这需要管理员权限（DC的域权限或本地权限）或KRBTGT哈希。
  
## 利用场景
- 此技术可能会**绕过系统日志记录和安全监视设备**，如SIEM产品（因为影子DC采取的操作可能不会报告给这些传感器）。
- 该技术还可以用于**更改和删除备份数据**以及其他关联的元数据，以阻止深度分析(法医分析)forensic analysis。
- 攻击者还可以利用此技术执行**SID历史记录注入**和操纵AD对象（如帐户，访问控制列表，模式schemas）以**建立持久性后门**。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- **网络流量**：
  - 监视和分析与DC之间以及DC与非DC主机之间的**数据复制**（例如，对`DrsAddEntry`、`DrsReplicaAdd`，尤其是`GetNCChanges`的调用）相关的网络流量。DC复制会每15分钟自动进行一次，但也可以由攻击者或合法的紧急更改（如修改密码）触发。
  - 监视和警告AD**对象复制**（审核详细目录服务复制事件Audit Detailed Directory Service Replication `Events 4928/4929`）。
- **目录状态**：利用AD目录同步（DirSync），监视使用AD复制cookies导致的目录状态更改。
- **Configuration**：对AD模式的配置`Configuration`进行定期基线分析，并在创建`nTDSDSA`对象时发出警报。
- **SPN使用情况**：
  - 与目录复制服务（DRS,Directory Replication Service）远程协议接口（`GUID E3514235–4B06–11D1-AB04–00C04FC2DCD2`）关联的SPN可以在不记录的情况下设置。
  - 可以检测不在 DC 组织单元（OU,organizational unit）中的计算机对Kerberos服务主体名称（SPNs, Service Principal Names），尤其是与服务相关联的名称（以“GC/”开头）的使用情况，
  - 恶意的影子DC必须使用这两个SPN作为服务进行身份验证，才能成功完成复制过程。
***
### Deobfuscate/Decode Files or Information （反混淆/解码) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1140/)

## 背景
- 攻击者可能会使用混淆文件或信息来隐藏入侵的分析结果，根据传入信息的利用方式，可能需要使用单独的机制来解码或模糊处理该信息。这样做的方法包括恶意软件内置功能、脚本、PowerShell或使用系统上存在的程序。

## 利用场景
- 示例之一是使用certutil解码隐藏在证书文件中的远程访问工具的可执行文件。
- 另一个示例是使用Windows `copy /b` 命令将二进制片段重新组装为恶意负载。
- 为了防止检测，有效负载可能被压缩，存档或编码。这些有效负载使用了混淆文件或信息技术，可以在初始访问期间与之后**逃避检测**。
- 有时，作为**用户执行**的一部分，可能需要用户打开灯操作以对其进行去混淆或解码处理。可能还要求用户输入密码以打开由攻击者提供的受密码保护的压缩/编码文件。
- 对手也可以使用压缩或存档脚本，例如Javascript。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 如果被混淆/加密的信息中心包含恶意软件中并使用**Windows API**，则在操作之前或之后尝试检测恶意行为，可能会取得比分析加载的库或API调用执行更好的结果。
- 如果使用**脚本**，则需要收集脚本进行分析。
- 对**执行过程和命令行**监视，以检测与脚本和系统实用程序有关的潜在恶意行为（如certutil）。
- 监视**常见存档文件应用扩展程序**（如Zip和RAR存档工具的应用和扩展程序）的执行文件路径和命令行参数，并与其他可疑行为关联，以减少来自正常用户和管理员行为的误报。
***
### Disabling Security Tools (瘫痪安全服务) (All)
>[原文链接](https://attack.mitre.org/techniques/T1809/)

## 背景
- 攻击者可能会禁用安全服务工具，以避免对其检测。

## 利用场景
- 关闭安全软件或事件日志记录过程；
- 删除注册表项，导致工具不会在运行时启动；
- 或采取其他方法来干扰安全扫描或事件报告。

## 防御方式
缓解|描述
:--:|:--
文件目录权限|确保适当的进程、注册表和文件权限配置
用户帐号权限|确保用户权限配置最小化
## 检测
- 监视**进程和命令行参数**以查看安全工具是否被杀死或停止运行。
- 监视**注册表编辑器**，是否有对与安全工具相关服务项和启动程序的修改。
- 安全工具缺少日志或事件文件报告。

***

### DLL Search Order Hijacking (DLL搜索顺序劫持) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1038/)
同3 Privilege Escalation
***


### DLL Side-Loading (DLL旁路加载) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1480/)

## 背景
- 程序可以运行时加载指定的的DLL。错误与模糊的指定会产生问题。
- 当WinSxS(Windows并行清单)对要加载的DLL的特性不够明确时，会发生旁加载漏洞。
- 攻击者可能会利用容易受到侧向加载的合法程序来加载恶意DLL。

## 利用场景
- 合法受信的系统软件进程中，掩盖执行的操作。

## 防御方式
缓解|描述
:--:|:--
审计|使用Windows的sxstrace.exe以及手动检查，检测清单文件中是否存在软件旁路加载漏洞。
文件目录权限|在写保护位置安装软件。
更新|定期对系统与软件进行更新。

## 检测
- 监视进程是否存在异常活动（如不使用网络的进程连接网络）。
- 跟踪DLL的元数据（如哈希），并将在进程执行时加载的DLL与以前的执行进行比较，检测与补丁或更新无关的可疑差异。

### Execution Guardrails (执行边界) (All)
>[原文链接](https://attack.mitre.org/techniques/T1480/)

## 背景
- 执行边界会根据目标特定环境存在的特定条件来限制执行操作。确保仅对预定目标执行payload，并减少附带损害。
- 攻击者提供有关目标系统或环境的边界值，可能包括特定网络共享名称，附加物理设备，文件，已加入的Active Directory（AD）域，本地/外部IP地址等。

## 利用场景

- 通过利用特定于目标的值解密有效载荷，攻击者可以避免将解密密钥与payload一起打包或通过**潜在受监控的网络**连接发送，并且给payload**逆向**带来困难。
- 通常，护栏被用于控制恶意程序的运行环境与限制损害程度/范围，以**避免暴露**。
- 不同于典型的虚拟化/沙盒逃避，护栏根据可以做出**是否进一步参与**的决定，因为其指定的是针对特定目标的价值条件，而不是使其在任何环境中执行功能。

## 防御方式
- 执行护栏很难通过预防性控制减轻，因为它能保护目标外的数据不受损害。
- 如果应保护的目标明确，则要致力于防止攻击工具在攻击链中更早的运行，并在受到损害时识别后续恶意行为。

## 检测
- 监视在收集各种系统信息或执行其他形式信息收集（特别是在短时间内）的可疑进程。

## 补充：环境密钥 Environmental keying
- 环境密钥是一种类型的护栏，用于从给定计算环境的特定值生成加/密密钥的加密技术。参数从给定环境的特定元素派生，并用于为加密的payload生成解密密钥。
- 参数可以从**特定**的网络共享、物理设备、软件/软件版本、文件、已加入的AD域、系统时间、本地/外部IP地址等元素中**得出**，通过参数**生成解密密钥**。
- 将**加密的payload**传递给目标，该目标将在执行之前使用目标的特定参数来解密有效负载。
- 环境密钥可以使**沙箱检测、反病毒检测、众测和逆向工程**等变得困难。以减慢事件响应速度，并帮助对手隐藏TTP(tactics, techniques, and procedures 战术，技术和程序)。

***

### Exploitation for Defense Evasion (漏洞利用免杀) (All)
>[原文链接](https://attack.mitre.org/techniques/T1211/)

## 背景
- 攻击者利用程序，服务或操作系统软件/内核本身内的程序漏洞来**执行payload**。
- 利用安全防御软件存在的漏洞，来**禁用或规避**它们。

## 利用场景
- 攻击者利用程序，服务或操作系统软件/内核本身内的程序漏洞来**执行payload**。
- 利用安全软件存在的漏洞，来**禁用或规避**它们。
- 通过事先侦查和在系统被入侵中执行防御软件发现(Security Software Discovery)，对环境中存在的特定安全软件进行攻击。

## 防御方式
缓解|描述
:--:|:--
隔离与沙箱|通过使用沙箱技术，增加攻击者利用未发现未修补的漏洞推进攻击过程的困难。虚拟化和微分段技术也可以缓解某些类型攻击影响。但这些系统中仍然存在其他利用和弱点的风险。
漏洞利用防护|Windows Defender漏洞利用防御WDEG、增强缓解经验工具包EMET，等针对漏洞利用过程行为的安全应用程序，可以减轻部分威胁。控制流完整性检查也可以识别和阻止软件攻击发生，但依赖于软件架构与程序二进制文件兼容性，可用性较低。
威胁情报|建立强大的网络威胁情报体系，以确定攻击类型与威胁级别，识别与特定组织相关的0day攻击。
更新|通过补丁管理定期更新软件与系统。

## 检测
- 基于系统**行为**
  - 在系统被入侵不久后发生，以掩护之后可能用到的其他攻击工具；
  - 成功率不高，可能导致软件运行不稳定或崩溃；
  - 磁盘可疑行为、试图隐藏的进程注入等漏洞成功利用的特征。

## 补充：微分段技术
- [相关链接](https://www.jianshu.com/p/1921a32afd19)
- 微分段(Micro-segmentation)是随着网络虚拟化提出的一种安全技术，通过应用该技术，能够提供在工作负载级别(workload level)上使能精细安全策略控制来保障用户业务安全。
- 使用微分段技术的一个显著好处就是能够将安全能力集成到虚拟化工作负载中，无须硬件设备(硬件防火墙）介入，也意味着将安全策略集成到虚拟网络(virtual network)、虚拟主机(VM)、操作系统以及其他虚拟安全实例中来提供安全。

***

### Extra Window Memory Injection 
>[原文链接](https://attack.mitre.org/techniques/T1181/)

同3 Privilege Escalation

***

### File and Directory Permissions Modification (文件目录权限修改) (All)
>[原文链接](https://attack.mitre.org/techniques/T1222/)
## 背景
- 文件和目录权限通常由文件目录所有者指定的**自由访问控制列表DACL**管理。
- DACL的实现可能因平台而异，但通常会明确指定用户/组可以执行的操作，如读写执行等。

## 利用场景
- **修改指定访问权限**，以修改、替换或删除特定的文件和目录。需要根据现有权限或提权来获得文件所有权。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- **监测**所有修改DACL和文件/目录所有权的尝试；
  - Windows中使用`icacls`、`takeown`、`attrib` 和PowerShell `Set-Acl`命令
  - 在MacOS/Linux中使用`chmod`、`chown`命令。
  - 以上许多是内置的系统程序且可能会生成高误报，因此应与系统正常运行基线比较，并将权限修改与其他恶意活动指示相关联。
- 对包含关键二进制/配置文件的文件夹，启用文件/目录权限**更改审核**。
- **审计Windows安全日志**（`Event ID 4670`)。

## 补充：SD&安全标识符&ACL
- **SD**：在Windows系统中，用一个安全描述符((Secrity Descriptors)的结构来保存其权限的设置信息，简称为SD，在Windows SDK中的结构名是SECURITY DESCRIPTOR", 是包括了安全设置信息的结构体。一个安全描述符包含以下信息:
  - **安全标识符**(Security dentifiers),用于记录安全对象的ID。简称为SID。
  - **DACL**(Discretionary Access ControlList,自由访问控制列表)，指出了允许和拒绝某用户或组的存取控制列表。当一个进程需要访问安全对象，系统就会检查DACL来决定进程的访问权。如果一个对象没有DACL,那么任何人都可以拥有完全的访问权限。
  - **SACL**(System Access ControlList,系统访问控制列表)，指出了在该对象上的一组存取方式(如，读、写、运行等)的存取控制权限细节的列表。还有其自身的一些控制位。SACL中的ACE能够产生访问尝试失败或成功的时候产生评估记录，在将来的release中， SACL在未授权用户尝试访问一个对象的时候发出警告
- DACL和SACL构成了整个**访问控制列表Access Control List**, 简称ACL, ACL中的每一项为**ACE(Access Control Entry)安全访问实体**。

***

### File Deletion (文件删除) (All)
>[原文链接](https://attack.mitre.org/techniques/T1107/)

## 背景
- 攻击者在系统抛出或创建的恶意软件，工具或其他非本机原生文件，可能会留下入侵痕迹。
- 在入侵过程中删除这些文件以保持其少量占用空间，或在入侵后的清理过程中最终将其清除。
  
## 利用场景
- 使用本机cmd函数如DEL，安全删除工具如Windows Sysinternals SDelete或其他第三方文件删除工具。
- 某些监视工具可能会收集命令行参数，但因DEL是cmd.exe中的本机函数，可能不会捕获DEL命令，。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- **监视命令行**删除功能，以使其与二进制文件或攻击者可能删除并删除的其他文件相关联。
- **监视**攻击者可能会引入目标网络系统的，尚未存在的已知与**安全删除工具**。

***

### File System Logical Offsets (文件系统逻辑偏移) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1006/)
## 背景
- Windows允许程序直接访问逻辑卷。
- 具有直接访问权限的程序可以通过分析文件系统数据结构直接从驱动器读取和写入文件。
  
## 利用场景
- 绕过**Windows文件访问控制**以及**文件系统监视工具**。
- 如NinjaCopy可以在**PowerShell中执行**这些操作。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- **监视句柄handle**，仅在进程创建的驱动器卷上打开，以确定它们何时可以直接访问逻辑驱动器
- **监视进程与命令行参数** ，检测可以从逻辑驱动器复制文件并逃避常见文件系统保护的操作
- 对**PowerShell脚本**进行额外的**日志记录**。

## 补充：句柄
- 一个句柄是指使用的一个唯一的整数值，即一个4字节(64位程序中为8字节)长的数值，来标识应用程序中的不同对象和同类中的不同的实例，如，一个窗口，按钮，图标，滚动条，输出设备，控件或者文件等。
- 应用程序能够通过句柄访问相应的对象的信息，但是句柄不是指针，程序不能利用句柄来直接阅读文件中的信息。
- 如果句柄不在I/O文件中，它是毫无用处的。
- 句柄是Windows用来标志应用程序中建立的或是使用的唯一整数，Windows大量使用了句柄来标识对象。

***

### Gatekeeper Bypass (Mac门禁(Gatekeeper)绕过) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1144/)
## 背景
- 在macOS和OS X中，从Internet下载的应用程序或程序时在名为`com.apple.quarantine`的文件上设置了特殊属性。Apple Gatekeeper防御程序会在执行时读取此属性，并向用户提示是否允许执行。
- 可以通过`xattr`命令`xattr/path/to/MyApp.app for com.apple.quartiance`检查隔离标志的存在。
- 给定sudo权限，这个属性可以用`xattr`删除，`sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app`。

  
## 利用场景
- 从USB闪存、光盘、外部硬盘驱动器和本地网络共享的驱动器，加载到系统上的应用程序不会设置此标志。此外，网站挂马/路过下载(drive-by download)等方式也不一定对其进行设置。
- 给定sudo权限，这个属性可以用`xattr`删除，`sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app`。

## 防御方式
缓解|描述
:--:|:--
安装限制|设置阻止未通过Apple Store下载的应用程序运行

## 检测
- 监视`com.apple.quarantine`，由**用户**而不是操作系统**删除标志**的行为；
- 监视如使用`xattr`**修改扩展文件属性**的程序尝试；
- 将删除与修改行为与其他恶意事件相**关联**。

***

### Group Policy Modification (组策略编辑)(Windows)
>[原文链接](https://attack.mitre.org/techniques/T1484/)
## 背景
- 组策略允许集中管理 **Active Directory (AD,域控制器)** 中的用户和计算机设置。
- **GPO (Group Policy Objects,组策略对象)** 是用于组策略设置的容器，该组策略设置由存储在可预测网络路径中的文件组成`\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\`。
- 默认情况下，域中的所有用户帐户都具有读取GPO的权限。可以将GPO访问控制权限（如写权限）分配给域中的特定用户或组。

## 利用场景
- 恶意GPO修改可用于实施**计划任务Scheduled Task**，**禁用安全工具Disabling Security Tools**，**远程文件复制Remote File Copy**，**创建帐户Create Account**，**服务执行Service Execution**等。
- 修改`<GPO_PATH>\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml`，利用`New-GPOImmediateTask`等公开的脚本通过修改GPOs自动化创建恶意**计划任务**
- 如在`<GPO_PATH>\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf`中调整SeEnableDelegationPrivilege, 修改特定用户的权限以修改GPOs，实现完全控制的AD后门。

## 防御方式
缓解|描述
:--:|:--
审计|使用如Bloodhound等审核工具来限制GPO权限滥用
用户帐号管理|考虑实施WMI和安全筛选(security filtering)，调整GPO策略应用于哪些用户和计算机

## 检测
- 使用Windows事件日志监视目录服务更改
  - Event ID 5136 - A directory service object was modified 目录服务对象已被修改
  - Event ID 5137 - A directory service object was created 目录服务对象已创建
  - Event ID 5138 - A directory service object was undeleted 删除目录服务对象失败
  - Event ID 5139 - A directory service object was moved 目录服务对象已移动
  - Event ID 5141 - A directory service object was deleted 目录服务对象已删除
- 识别GPO滥用通常会伴随的其他行为，
   - 如“计划任务”，将与之关联的事件得以检测。
   - 也可以在与分配给新登录的特权（Event ID 4672）和用户权限的分配（Event ID 4704）相关的事件中搜索随后的权限修改
   - 对SeEnableDelegationPrivilege的修改。

## 补充：WMI
- **WMI**(Windows Management Instrumentation,Windows管理规范)是一项核心的 Windows 管理技术；用户可以使用 WMI 管理本地和远程计算机。

***

### Hidden Files and Directories (隐藏文件/目录) (All)
>[原文链接](https://attack.mitre.org/techniques/T1158/)

同第四部分“Persistence”

***

### Hidden Users (隐藏用户) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1147/)
## 背景
- macOS中的每个用户帐户都有一个与之关联的用户ID。创建用户时，可以指定该帐户的用户ID。
- `/Library/Preferences/com.apple.loginwindow`调用`Hide500Users`中有一个属性值，可防止用户ID为500和更低的用户出现在登录屏幕上。

## 利用场景
- 通过使用用户ID低于500 的“ 创建帐户”技术并启用此属性（将其设置为“是”），对手可以更轻松地隐藏其用户帐户：`sudo dscl . -create /Users/username UniqueID 401`

## 防御方式
缓解|描述
:--:|:--
操作系统配置|如果计算机加入了域，组策略可以帮助限制创建或隐藏用户的能力。阻止`/Library/Preferences/com.apple.loginwindow` `Hide500Users`值的修改将强制所有用户可见。

## 检测
- 此技术可防止新用户出现在登录屏幕上，但新用户的所有其他标志仍然存在。如用户仍然获得home目录，并将出现在身份验证日志中。

***

### Hidden Window (隐藏窗口) (All)
>[原文链接](https://attack.mitre.org/techniques/T1143/)
## 背景
- 在某些情况下，可以隐藏通常在应用程序执行时显示的窗口。系统管理员可以利用它来避免执行管理任务时影响用户的工作环境。
- **Windows**
  -Windows中的脚本语言如PowerShell，Jscript和VBScript可以使窗口隐藏。如`powershell.exe -WindowStyle Hidden`。
- **Mac**
  - 属性列表(plist)文件中列出了在macOS上运行的应用程序配置。
  - 如`apple.awt.UIElement`允许Java应用程序阻止该应用程序的图标出现在Dock中。
- **Linux**
  - 安装了可视化桌面的Linux系统会有同样的问题。

## 利用场景
- 攻击者可能滥用操作系统功能来向用户隐藏其他可见的窗口，以免提醒用户系统上的攻击者活动。

## 防御方式
缓解|描述
:--:|:--
执行限制|使用防病毒软件限制或限制程序执行。在MacOS上，白名单程序带有plist标记，其他程序应视为可疑。

## 检测
- **监视进程和命令行参数**是否有指示隐藏窗口的操作。
- 在**Windows**中，**启用并配置事件日志记录和PowerShell日志记录**以检查隐藏的窗口样式。
- 在**MacOS**中，plist文件是具有特定格式的ASCII文本文件，因此它们相对容易解析。通过**文件监视**，检查`apple.awt.UIElementplist`中的和其他可疑plist文件中的plist标签并标记。

***

### HISTCONTROL (历史控制) (Linux&macOS)
>[原文链接](https://attack.mitre.org/techniques/T1148/)
## 背景
- `HISTCONTROL`环境变量踪history命令应保存的内容，并在用户注销时保存在`~/.bash_history`中。

## 利用场景
- 将`HISTCONTROL`设置为`ignorespace`，配置为忽略以空格开头的命令；
- 将`HISTCONTROL`设置为`ignoredups`，配置为忽略重复的命令；
- 在某些Linux系统中，默认情况下将`HISTCONTROL`设置为`ignoreboth`，包括前面两个配置。
- `HISTCONTROL`在macOS上默认情况下不存在，但可由用户设置。


## 防御方式
缓解|描述
:--:|:--
环境变量权限|防止用户更改`HISTCONTROL`环境变量。
操作系统配置|将`HISTCONTROL`环境变量设置为"ignoredup"，而不是" ignoreboth"或"ignorespace"。

## 检测
- 基于行为
  - 将用户会话与`.bash_history`中明显缺少新命令的用户相关联。
  - 用户检查或更改其`HISTCONTROL`环境变量。

***

### Image File Execution Options Injection (图像文件执行选项注入) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1183/)

同第三部分“Persistence”

***

### Indicator Blocking (阻断指标收集) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1054/)
## 背景
- 攻击者可能试图阻止通常由传感器捕获的指标或事件被收集和分析。

## 利用场景
- **恶意篡改**，通过篡改事件记录或控制数据监视的设置，**禁用主机传感器**，如Windows事件跟踪(ETW)，这些设置可能存储在系统中的配置文件和注册表中，也可以通过如PowerShell或Windows Management Instrumentation等进行访问。
- 通过多种方式来实现**ETW中断**，但最直接的方法是使用`PowerShell Set-EtwTraceProvider cmdlet`定义条件，或直接与注册表交互以进行更改。
- 对于基于网络的指标报告中，**阻止与报告相关的流量**，以防止集中分析。如停止负责转发本地监控的进程，或创建基于主机的防火墙规则以阻止流量流向负责汇总事件的特定主机(SIEM)。

## 防御方式
缓解|描述
:--:|:--
访问控制|使用适当的权限和访问控制来保护事件跟踪器/转发器、防火墙策略和其他关联的机制。
软件配置|以周期性间隔（如时间/登录等）自动重启转发，并将适当的更改管理应用于防火墙规则和其他相关系统配置。
用户帐号管理|确保事件跟踪器/转发器、防火墙策略和其他关联的机制受到适当权限和访问控制的保护，且不能被用户帐户操纵。

## 检测
- 从主机传感器**检测缺少报告的活动**。如突然停止或仅报告部分类型数据。
- 根据收集的主机信息的类型，**检测触发进程停止或连接被阻止的事件**。
- Sysmon将在其配置状态已更改(Event ID 16)时记录日志
- WMI(Windows Management Instrumentation,Windows管理工具)可以用于订阅ETW提供程序，该日志记录特定跟踪会话中提供删除服务的任何程序。
- 通过监视注册表项，检测ETW中的更改`HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AUTOLOGGER_NAME{{PROVIDER_GUID}}`

***

### Indicator Removal from Tools (删除导致检测的指标) (All)
>[原文链接](https://attack.mitre.org/techniques/T1066/)
## 背景
- 如果恶意软件被检测和隔离，或通过其他方式被缓解，攻击者可能借此**确定恶意工具被检测到的原因**（指标）。
- 通过**删除指标**来修改和升级工具，以**规避再次检测**和**绕过使用相同检测机制**的设备。

## 利用场景
- 当恶意程序因文件签名被隔离，通过软件打包 Software Packing 等方式改变文件签名，之后重用。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 将**初始检测**视为潜在危害更大入侵的**指示**，**假设威胁事件不单一存在**，与其他可能的入侵行为相关联。

***

### Indicator Removal on Host (删除主机中收集的指标) (All)
>[原文链接](https://attack.mitre.org/techniques/T/)
## 背景
- 攻击者可能会**删除或更改主机系统上生成的工件**，包括日志和可能捕获到的文件如隔离区的恶意软件。

## 利用场景
- 删除日志，如典型的Windows事件或Linux/macOS文件Bash History和/ var / log / *）。
- 干扰事件记录和其他用于入侵活动检测通知的操作可能会损害安全解决方案的完整性，**导致事件无法报告**。
- 由于缺乏足够的数据来确定发生了什么，也可能**使深度分析和事件响应变得困难**。

## 防御方式
缓解|描述
:--:|:--
敏感信息加密|在本地和传输过程中对Event文件进行混淆/加密，避免向对手提供反馈。
远程数据存储|将事件自动转发到日志服务器或存储数据库，防止攻击者在本地系统上定位和操纵数据的情况。尽量减少事件报告的时间延迟，避免在本地系统上长时间存储。
文件/目录访问控制|使用适当的权限和身份验证保护在本地存储的生成的Event文件，并通过防止特权升级来限制攻击者提权概率。

## 检测
- 通过文件系统监视，检测指标文件的删除或修改。
- 如删除Windows事件日志(通过本机二进制文件、API函数或PowerShell)可能会生成事件(事件ID 1102：“清除了审计日志”`Event ID 1102: "The audit log was cleared"` ).

## 补充：Windows事件日志
  - Windows事件日志是计算机警报和通知的记录。
  - Microsoft将事件定义为“系统或程序中任何需要通知用户或将条目添加到日志的重大事件(any significant occurrence in the system or in a program that requires users to be notified or an entry added to a log)”
  - 有三个系统定义的事件：系统System，应用程序Application和安全Security。
  - 进行与帐户管理，帐户登录和目录服务访问等相关的操作的对手可以选择清除事件以隐藏其活动。
  - 可以使用以下实用程序命令清除事件日志：
    `wevtutil cl system`
    `wevtutil cl application`
    `wevtutil cl security`
  - 日志也可以通过其他机制清除，例如PowerShell。
  
***

### Indirect Command Execution (间接命令执行) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1202/)
## 背景
- 可以使用各种Windows程序，**不调用cmd**执行命令。

## 利用场景
- 攻击者可以滥用这些功能进行防御规避，**破坏检测**或**减轻**如组策略等限制cmd执行和与恶意payload相关的文件扩展名的机制的**控制**，导致**任意命令执行**
- 如对于文件，使用程序兼容性助手(pcalua.exe)、适用于Windows的Linux子系统(WSL,Windows Subsystem for Linux)等组件及其他程序，可以从命令行界面、运行窗口或通过脚本**调用程序**和**命令执行**。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 监视和分析基于主机的检测机制中的日志(如Sysmon)，关注是与调用程序/命令/文件，或生成子进程/网络连接相关联的参数导致的进程创建等事件。

### Install Root Certificate (安装根证书) (All)
>[原文链接](https://attack.mitre.org/techniques/T1130/)
## 背景
- **根证书**在公钥加密中用于标识根证书颁发机构CA。安装根证书后，系统或应用程序将信任由根证书签名的根信任链中的证书。
- 证书通常用于在Web浏览器中建立安全的TLS/SSL通信。当用户浏览提供不可信证书的网站时将显示错误消息，以警告用户安全风险。根据安全设置，浏览器可能不允许用户建立与该网站的连接。

## 利用场景
- 攻击者可以在**脆弱的系统**上安装根证书，来**避免**系统连接到攻击者控制的服务器时的**安全警告**，诱导用户访问非法网站并窃取信息。
- 在软件**供应链**中安装非典型证书，并与恶意软件或广告软件一同使用，提供**中间人攻击**的条件(拦截通过安全TLS/SSL通信传输的信息的能力)。
- 根证书（及其关联的链）被**克隆和重新安装**的情况。克隆的证书链将携带许多与源相同的数据特征，并可用于**对恶意代码签名**，使恶意代码能绕过基于签名的安全工具(如Sysinternals、antivirus等)。
- 在macOS中，Ay MaMi恶意软件通过`/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/malicious/cert`将恶意证书作为受信任的根证书安装到系统keychain中。

## 防御方式
缓解|描述
:--:|:--
操作系统配置|使用Windows组策略管理根证书，将`HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots`的Flags值设置为1，以防止非管理员用户在自己的HKCU(每个用户的注册表项HKEY_CURRENT_USER)证书存储区中进行进一步根证书安装。
软件配置|使用HTTP公钥锁定(HPKP)技术防止中间人攻击

## 检测
- 监视可能的恶意活动在系统上安装的新证书(系统的根证书不太可能经常更改)。
- 检查新系统上的预安装证书，以确保不存在不必要或可疑的证书。
  - Microsoft在线并通过`authroot.stl`提供了可信任的根证书列表。
  - 使用Sysinternals Sigcheck `sigcheck.exe -tuv` dump出证书存储的内容，并列出未在Microsoft证书信任列表的有效证书。
- 已安装的根证书位于注册表中的`HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates\`和`[HKLM or HKCU]\Software[\Policies]\Microsoft\SystemCertificates\Root\Certificates\`。
- 根证书的一个子集在Windows系统间是一致的，可用于比较：
  - 18F7C1FCC3090203FD5BAA2F861A754976C8DD25
  - 245C97DF7514E7CF2DF8BE72AE957B9E04741E85
  - 3B1EFD3A66EA28B16697394703A72CA340A05BD5
  - 7F88CD7223F3C813818C994614A89C99FA3B5247
  - 8F43288AD272F3103B6FB1428485EA3014C0BCFE
  - A43489159A520F0D93D032CCAF37E7FE20A8B419
  - BE36A4562FB2EE05DBB3D32323ADF445084ED656
  - CDD4EEAE6000AC7F40C3802C171E30148030C072
***


### InstallUtil (InstallUtil利用) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1118/)

同第二部分“Execution”

### Launchctl (Launchctl利用) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1152/)

同第二部分“Execution”，第三部分"Persistence"

***

### LC_MAIN Hijacking
>[原文链接](https://attack.mitre.org/techniques/T/)
## 利用场景


## 防御方式


## 检测


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
