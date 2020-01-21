# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

***



## Defense Evasion (防御规避)

>攻击者试图避免被发现。

**防御规避** 是指攻击者在**整条攻击链**中避免被发现的技术。包括**免杀**(uninstalling/disabling 卸载/瘫痪安全软件)和**加固**(obfuscating/encrypting 混淆/加密脚本和数据)，攻击者同样**武器化**利用受信任的进程来隐藏和伪装恶意软件。

***

### Access Token Manipulation (访问令牌操纵) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1134/)


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

同第三部分“Persistence”

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

***

### Launchctl (Launchctl利用) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1152/)

同第二部分“Execution”，第三部分"Persistence"

***

### LC_MAIN Hijacking (LC_MAIN劫持) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1149/)
## 背景
- 从OS X 10.8开始，mach-O二进制文件引入了一个名为LC_MAIN的新头文件，指向二进制文件的执行入口。
- 之前的版本由 LC_THREAD 和 LC_UNIXTHREAD 两个标头实现。

## 利用场景
- 二进制文件的入口点可能被劫持，将初始执行流引到**恶意附加项**（另一个section或code cave），然后**返回到初始入口点**。
- 通过以这种方式修改二进制文件，因为文件名和应用程序路径仍然相同，可以**绕过应用程序白名单**。

## 防御方式
缓解|描述
:--:|:--
代码签名|对所有应用程序上的签名代码强制使用有效的数字签名，并且仅使用来自受信任方签名的信任应用程序。

## 检测
- **校验和和签名验证**。修改LC_MAIN入口点或添加其他LC_MAIN入口点会使文件签名无效，并且可以检测到。
- 收集正在运行的进程信息，并与已知的应用程序进行比较以查找可疑行为。

***

### Masquerading (伪装) (All)
>[原文链接](https://attack.mitre.org/techniques/T1036/)
## 背景
- 当可执行文件的名称或位置（合法的或恶意的）被操纵或滥用以逃避防御和观察时，就会出现伪装。

## 利用场景
- 将可执行文件放在通常受信任的目录中，或者伪造一个合法或无害的的受信程序名，以**绕过依赖文件名或路径信任可执行文件的工具**，并将文件名与被认为合法的内容相关联，使维护者和系统管理员认为文件是良性的。
- 使用从右向左覆盖（**RTLO或RLO**）字符（U+202E）诱骗用户，执行被认为是良性但实际上是可执行代码的文件。
- 攻击者可能会修改二进制文件的元数据，包括图标，版本，产品名称，描述和版权等字段，以更好地融入环境并增加欺骗安全分析人员或产品的机会。
- **Windows**
  - 使用合法实用程序（如rundll32.exe）的重命名副本。
  - 将合法实用程序移至其他目录并重新命名以避免基于从非标准路径执行的系统实用程序的检测。
  - 在`C:\Windows\System32`目录，赋予恶意文件受信任二进制名称，如explorer.exe、svchost.exe。
- **Linux**
  - 在启动之后将恶意二进制文件运行进程名称更改为受信或良性进程的名称。
  - 在`/bin`目录，赋予恶意文件受信任二进制名称，如rsyncd、dbus-inotifier。


## 防御方式
缓解|描述
:--:|:--
代码签名|二进制文件需要签名
执行预防|使用需要文件名外属性的白名单工具限制程序执行
访问控制|使用文件系统访问控制来保护文件夹如`C:\Windows\System32`等文件夹。

## 检测
- 检查**文件哈希**，关注与预期的哈希值不匹配的文件。
- 执行**文件监控**，关注具有已知名称但在不寻常位置的文件。
- 检查在更新或补丁程序之外**修改的文件**.
- 磁盘上的**文件名与二进制文件的PE元数据的文件名不匹配**(查看InternalName、OriginalFilename、ProductName)的情况，可能表示二进制文件在编译后已重命名。
- 关注程序要使用的已知**命令行参数**而不是可能具有的名称，这些参数是不同的，因为它将具有更好的检测率。
- 对于RTLO，检测文件名中**RTLO字符的通用格式**(如“\u202E”，“[U + 202E]”和“％E2％80％AE”)，并确保RTLO字符**不会被解释**，而是直接打印包含该字符的真实名称。

## 补充 (RTLO)
- RTLO是一个非打印字符，它会导致后面的文本**反向显示**。
  - 如，一个名为March 25\u202Excod.scr的Windows屏幕保护程序文件将显示为March 25 rcs.docx。
  - 名为photo_high_re\u202Egnp.js的JavaScript文件将显示为photo_high_resj.png。
- 这种技术通常用于钓鱼附件，以欺骗最终用户和防御者。在许多有针对性的入侵企图和犯罪活动中都可以看到RTLO字符的使用。
- RTLO也可以在Windows注册表中使用，其中regedit.exe显示相反的字符，但默认情况下命令行工具reg.exe不显示。

***

### Modify Registry (修改注册表) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1112/)
## 背景
- 攻击者与Windows注册表进行交互，以在注册表项中**隐藏配置信息**、作为**清理**工作的一部分或作为**持久性Persistence**和**执行Execution**的一部分。
- 访问注册表的特定区域取决于**帐户权限**，有些需要管理员级别的访问权限。
- 内置的Windows命令行程序如**Reg**、包含通过Windows API与注册表交互的功能的程序如如**远程访问工具**，可用于本地或远程注册表修改，。
  
## 利用场景
- 在注册表项中**隐藏配置信息**、作为**清理**工作的一部分或作为**持久性Persistence**和**执行Execution**的一部分。
- 注册表修改还包括**隐藏key**的操作，如以空字符开头的key名称会导致错误或在使用Reg/其他使用Win32 API程序读取时被忽略。可以通过滥用伪隐藏的key来**隐藏**建立持久性的**payloads和命令**。
- 远程修改系统的注册表，可以作为执行文件横向移动的一部分。它要求远程注册表服务在目标系统上运行，并通常需要**有效帐户**(Valid Accounts)，以及访问远程系统的**Windows管理员共享**(Windows Admin Shares)以进行RPC通信的权限。

## 防御方式
缓解|描述
:--:|:--
限制注册表权限|为注册表配置单元设置了适当的权限，防止用户修改可能导致权限提升的系统组件的键。

## 检测
- 监视**注册表行为**
  - 对注册表的修改是正常的，并且通常在Windows操作系统的整个使用过程中进行。
  - 对特定键启用**注册表审核**，以便在值发生更改时生成可警报事件`Event ID 4657`(使用Reghide或其他规避方法创建值时可能不会触发此事件)。
  - 关注在Windows启动时加载与已知软件、程序补丁周期等不相关的软件的注册表项的**更改**
  - 关注对启动文件夹中文件的**添加或更改**。
  - 关注**创建新服务**和**修改**现有二进制**路径**指向的行为。如果更改了与服务相关的条目，则随后可以通过本地或远程服务启动或重启以执行文件。
- 监视**进程和命令行参数**
  - 具有内置功能的远程访问工具可以直接与Windows API交互以收集信息；
  - 也可以通过Windows系统管理工具（如Windows Management Instrumentation和PowerShell）来获取信息；
  - 在操作系统中配置其他日志记录功能，收集必要的信息以进行分析。
- 监视与**隐藏注册表项**（如Reghide）关联的进程，命令行参数和API调用。使用本机Windows API调用或如Autoruns、RegDelNull等工具检查和清除恶意的隐藏注册表项。

***

### Mshta (Mshta利用) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1170/)

同第二部分“Execution”

***

### Network Share Connection Removal (网络连接删除) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1126/)
## 背景
- 根据不同的网络环境，网络共享连接可能很常见。
- 不再需要Windows共享驱动器和Windows Admin Shares连接时，可以将其删除。
- Net是一个示例实用程序，可通过`net use \system\share /delete`命令删除网络共享连接。

## 利用场景
- 删除不再有用的共享连接，以**清除痕迹**。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 监视通过SMB建立和删除的与远程共享相关的网络使用命令的**命令行调用**，包括Windows管理共享Windows Admin Shares的最佳实践。
- 捕获和解码系统之间的**SMB通信**，查找相关的网络共享会话和文件传输活动。
- **Windows身份验证日志**可用于确定何时及哪个账户建立了已验证的网络共享，并可用于将网络共享活动与其他事件关联，以调查潜在恶意行为。

***

### NTFS File Attributes (NTFS属性) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1096/)
## 背景
- NTFS格式的分区都包含一个主文件表MFT，该表维护分区上每个文件/目录的记录。
- MFT的条目为文件属性，如**扩展属性EA**和数据(存在多个数据属性时称为备用数据流ADS)，可用于存储任意数据甚至完整文件。

## 利用场景
- 攻击者可能会将恶意数据或二进制文件存储在**文件属性元数据**中，而不是直接存储在文件中。
- 可以**规避**某些防御措施，例如静态指示器扫描工具和防病毒软件。

## 防御方式
缓解|描述
:--:|:--
限制文件和目录权限|调整NTFS EA的读写权限，(应该对此进行测试以确保不妨碍常规OS操作)。

## 检测
- **深度分析**技术来识别存储在NTFS EA中的信息。监视对ZwSetEaFile和ZwQueryEaFile Windows API函数的调用以及用于与EA交互的二进制文件，并考虑定期扫描是否存在已修改的信息。
- 监视**使用Windows实用程序创建ads并与之交互**的方法。使用包含冒号的文件名监视操作（执行，副本等）。
  - 一些语法（如`file.ext:ads[.ext]`）通常与ADS相关联。
  - 有关可用于执行和创建ADS的实用程序的更详尽列表，请参见https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f。

***

### Obfuscated Files or Information (混淆的文件或信息) (All)
>[原文链接](https://attack.mitre.org/techniques/T1027/)
## 背景
- 攻击者可能试图通过加密，编码或其他方式混淆可执行文件或文件在系统中或传输中的内容，从而使其难以发现或分析。这是常见的行为，可以跨不同的平台和网络使用，以逃避防御。

## 利用场景
- Payload可能被**压缩，存档或加密**，以避免被检测到。这些payload可以在初始访问Initial Access期间和以后使用以减轻检测。
  - 可能需要用户采取行动才能打开反混淆/解码的文件或信息，以供用户执行。
  - 可能还要求用户输入密码以打开由攻击者提供的受密码保护的压缩/加密文件。
  - 攻击者也可以使用压缩或存档脚本，如JS。
- 对文件的某些部分进行**编码**以隐藏纯文本字符串。
- 将Payload**拆分**为看似良性的单独文件，这些文件仅在重新组合后才会执行恶意功能。
- **混淆**从Payload执行的**命令**或直接通过命令行界面执行的命令。环境变量，别名，字符和其他平台/语言特定的语义，可用于规避基于签名的检测和白名单机制。
- **隐写术**，将消息或代码隐藏在图像，音轨，视频剪辑或文本文件中的技术。

## 防御方式
缓解|描述
:--:|:--
防病毒/反恶意软件|使用Windows 10上的反恶意软件扫描接口（AMSI）分析处理/解释后的命令。

## 检测
- 检测混淆文件的**恶意活动**。除非混淆过程留下了可以用签名检测到的中间产物，否则很难检测文件混淆。如果无法检测到混淆本身，则有可能检测到导致混淆文件的恶意活动（如用于在文件系统上写入、读取或修改文件的方法）。
- 标记并分析包含**混淆指示符和已知可疑语法**（如未解释的转义字符'''^'''和'''"'''等）的命令。Windows'Sysmon和事件ID 4688显示进程的命令行参数。一些工具可以用来检测文件/Payload中的这些指标。
- **在网络上检测**Payload中用于初始访问的混淆。使用NIPS和电子邮件网关过滤识别压缩和加密的附件脚本。某些电子邮件附件引爆系统可以打开压缩和加密的附件。通过加密连接从网站传递的Payload需要加密的网络流量检查。

***

### Parent PID Spoofing	(父级PID欺骗) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1502/)

同第四部分“Privilege Escalation”
***

### Plist Modification (list修改) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1150/)

同第三部分，“Persistence”、第四部分“Privilege Escalation”
***

### Port Knocking (端口试探) (Linux&macOS)
>[原文链接](https://attack.mitre.org/techniques/T1205/)

同第三部分“Persistence”、第十部分“Command and Control”
***

### Process Doppelgänging (ProcessDoppelgänging代码注入) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1186/)
## 背景
- Black Hat欧洲2017大会上，两名来自enSilo公司的安全研究员介绍了一种新的代码注入技术,他们命名为“Process Doppelgänging”。
- Vista中引入了Windows事务NTFS(**TxF**)为执行安全文件操作的方法。
  - 为确保数据完整性，TxF仅允许一个事务处理的句柄在给定时间写入文件。
  - 在写句柄事务终止之前，所有其他句柄均与编写器隔离，并且只能读取打开该句柄时存在的文件的提交版本；
  - 为避免数据损坏，如果系统或应用程序在写事务期间失败，则TxF将执行自动回滚。
  - 尽管已弃用，从Windows 10开始，仍启用了TxF应用程序的编程接口API。
- ProcessDoppelgingäing分4个步骤实施：
  - Transact，事务处理–使用合法的可执行文件创建TxF事务，然后使用恶意代码覆盖文件。这些更改将被隔离，并且仅在事务上下文中可见。
  - Load，加载–创建内存的共享部分并加载恶意可执行文件。
  - Rollback，回滚–撤消对原始可执行文件的更改，从而有效地从文件系统中删除恶意代码。
  - Animate，执行–从内存的污染部分创建一个进程并启动执行。

## 利用场景
- 对手可以利用TxF来执行一个称为ProcessDoppelgingäing的**无文件的进程注入**变体。
- 与进程空心化Process Hollowing类似，ProcessDoppelgingäing涉及替换合法进程的内存，从而允许**隐藏执行恶意代码**，这些代码可以逃避防御和检测。
- ProcessDoppelgingäing使用TxF还**避免使用高度监控的API函数**，如`NtUnmapViewOfSection`、`VirtualProtectEx`和`SetThreadContext`。

## 防御方式
- 属于系统功能滥用，无法简单缓解。
  
## 检测
- **监视和分析**对`CreateTransaction`，`CreateFileTransacted`，`RollbackTransaction`和其他很少使用的**表示TxF活动的函数的调用**。ProcessDoppelgingäing还通过调用一个过时的、未记录的Windows进程加载器实现，如对NtCreateProcessEx和NtCreateThreadEx的调用以及用于在另一个进程（如WriteProcessMemory）中的内存的API调用，
- **扫描**在`PsSetCreateProcessNotifyRoutine`期间报告的**文件对象**，该文件对象在创建或删除进程时会触发回调，特别是寻找具有启用写访问权限的文件对象。还应考虑将内存中加载的文件对象与磁盘上的相应文件进行比较。
- **分析进程行为**，以确定某个进程是否正在执行其通常不执行的操作，例如打开网络连接，读取文件或其他可能与破坏后行为(post-compromise behavior)相关的可疑操作。

***

### Process Hollowing (冷注入/进程空心化) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1093/)
## 背景
- 当在挂起状态下创建进程然后取消其内存映射并用恶意代码替换时，就会发生Process Hollowing。

## 利用场景
- 与进程注入类似，恶意代码的执行在合法进程下被屏蔽，并且可能**逃避防御和检测分析**。
> [一个案例](https://www.freebuf.com/articles/system/154421.html)

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- **检测可以取消映射进程内存**的API调用（如`ZwUnmapViewOfSection`或`NtUnmapViewOfSection`）和**可以用于修改另一个进程内的内存**的API调用（如WriteProcessMemory）。
- **分析进程行为**，以确定某个进程是否正在执行其通常不执行的操作，例如打开网络连接，读取文件或其他可能与破坏后行为(post-compromise behavior)相关的可疑操作。

***

### Process Injection (进程注入) (All)
>[原文链接](https://attack.mitre.org/techniques/T1055/)

同第四部分“Privilege Escalation”
***

### Redundant Access (冗余访问) (All)
>[原文链接](https://attack.mitre.org/techniques/T1108/)

同第三部分“Persistence”
***

### Regsvcs/Regasm (Regsvcs/Regasm武器化) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1121/)

同第二部分“Execution”
***

### Regsvr32 (Regsvr32武器化) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1117/)

同第二部分“Execution”
***

### Rootkit (Rootkit) (All)
>[原文链接](https://attack.mitre.org/techniques/T1014/)
## 背景
- ROOTKITS是通过**拦截**（Hooking）和**修改**提供系统信息的操作系统API调用来隐藏恶意软件的存在的程序。
- Rootkits或rootkit启动点可以隐藏在操作系统或用户的**更底层**，包括管理程序、主引导记录和系统固件。

## 利用场景
- 攻击者可能使用rootkit来**隐藏**程序，文件，网络连接，服务，驱动程序和其他系统组件的存在。
- 目前已经在Windows，Linux和MacOS X系统上有发现Rootkit。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 某些rootkit保护功能可能**内置**在防病毒或操作系统软件中。
- 有专用的**rootkit检测工具**可查找特定类型的rootkit行为。
- **监视**是否存在**无法识别**的DLL，设备，服务以及对MBR的更改。

***

### Rundll32	(Regsvr32武器化) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1085/)

同第二部分“Execution”
***

### Scripting (恶意脚本) (All)
>[原文链接](https://attack.mitre.org/techniques/T1064/)

同第二部分“Execution”
***

### Signed Binary Proxy Execution (签名的二进制程序代理执行) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1218/)

同第二部分“Execution”
***

### Signed Script Proxy Execution (签名的脚本代理执行) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1216/)

同第二部分“Execution”
***

### SIP and Trust Provider Hijacking (SIP和受信供应链劫持)(Windows)
>[原文链接](https://attack.mitre.org/techniques/T1198/)

同第三部分“Persistence”
***

### Software Packing (软件打包)(All)
>[原文链接](https://attack.mitre.org/techniques/T1045/)
## 背景
- 软件打包是一种**压缩和加密**可执行文件的方法。打包可执行文件会**改变文件签名**，以避免基于签名的检测。
- 大多数解压技术都将内存中的可执行代码解压缩。
- 用于执行软件打包的实用程序称为打包程序，如MPRESS和UPX
- [一个更全面的列表](https://en.wikipedia.org/wiki/Executable_compression)，但对手可能会创建自己的包装技术，
- 攻击者可以使用**虚拟机软件保护**作为软件包的一种形式来保护其代码。虚拟机软件保护将可执行文件的原始代码转换为特殊格式，只有特殊的虚拟机才能运行。然后调用虚拟机来运行此代码。

## 利用场景
- 软件打包是一种**压缩和加密**可执行文件的方法。打包可执行文件会**改变文件签名**，以避免基于签名的检测。
- 攻击者可以使用**虚拟机软件保护**作为软件包的一种形式来保护其代码。虚拟机软件保护将可执行文件的原始代码转换为特殊格式，只有特殊的虚拟机才能运行。然后调用虚拟机来运行此代码。

## 防御方式
缓解|描述
:--:|:--
防病毒/反恶意软件|采用基于启发式的恶意软件检测，并设置策略为检测的恶意软件创建自定义签名。

## 检测
- 使用**文件扫描**来查找已知的软件打包程序或使用打包技术的文件。
- 因为合法软件也可能会使用打包技术来减小二进制大小或保护专有代码。

***

### Space after Filename (文件名后加空格)(MacOS&Linux)
>[原文链接](https://attack.mitre.org/techniques/T1151/)

同第二部分“Execution”
***

### Template Injection (模板注入)(Windows)
>[原文链接](https://attack.mitre.org/techniques/T1221/)
## 背景
- Microsoft的Open Office XML(**OOXML**)规范为**Office文档**(.docx，xl​​sx，.pptx)定义了一种基于XML的格式，以替换较旧的二进制格式(.doc，.xls，.ppt)。
- OOXML文件被打包在一起，压缩成各种XML文件（称为部分）的压缩文件，其中包含共同定义文档呈现方式的属性。
- 部件中的属性可以引用通过**联机URL访问**的共享公共资源。例如，模板属性引用一个文件，用作加载文档时获取的预格式化文档蓝图。

## 利用场景
- 攻击者可能会滥用该技术来**最初步的隐藏**要通过文档执行的恶意代码（Scripting）。加载到文档中的模板引用可以使Payload在加载文档时被获取并执行。
- 这些文档可以通过其他技术（如网络钓鱼附件和/或污染共享内容）传播，并且可以**避免静态检测**，因为在获取Payload之前不存在典型的指标（VBA宏、脚本等）。
- [示例](https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/)
- 此技术还可以通过注入SMB/HTTPS（或其他凭据提示）URL并触发身份验证尝试来**启用强制身份验证**。

## 防御方式
缓解|描述
:--:|:--
防病毒/反恶意软件|使用IPS、病毒防御系统和沙箱以防止文档获取和执行恶意Payload。
禁用宏|禁用Microsoft Office宏/活动内容，以防止执行文档中的恶意Payload，但可能不会减少强制身份验证对此技术的使用。
用户培训|培训对社交工程技术和钓鱼邮件的识别。

## 检测
- 分析**进程行为**，以确定Office应用程序是否正在执行某些操作，例如打开网络连接，读取文件，产生异常的子进程（如PowerShell）或其他可能与入侵后行为相关的可疑操作。

***

### Timestomp(修改时间戳)(All)
>[原文链接](https://attack.mitre.org/techniques/T1099/)
## 背景
- Timestomp是一种用于修改文件时间戳（修改，访问，创建和更改时间）的技术，通常是模仿同一文件夹中的文件。

## 利用场景
- 在攻击者创建的文件上执行此操作，模仿同文件夹下其他文件，以**欺骗**调查人员和文件分析工具。
- 与文件名伪装一起使用以**隐藏**恶意软件和工具。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 使用**文件修改监视**来检测时间戳，该技术收集监视收集有关文件句柄打开的信息，并可以比较时间戳值。

***

### Trusted Developer Utilities (受信的开发人员实用程序)(Windows)
>[原文链接](https://attack.mitre.org/techniques/T1127/)

同第二部分“Execution”
***

### Valid Accounts(有效账户)(All)
>[原文链接](https://attack.mitre.org/techniques/T1078/)

同第一部分“Initial Access”、第三部分“Persistence”、第四部分“Privilege Escalation”
***

### Virtualization/Sandbox Evasion(虚拟机/沙盒规避)(All)
>[原文链接](https://attack.mitre.org/techniques/T1497/)

同第七部分“Discovery”
## 背景
- 攻击者可能会检查是否存在虚拟机环境（VME）或沙箱，以**避免工具和活动被检测到**。
- 如果对手检测到VME，他们可能会**更改恶意软件**以**隐藏核心功能**或**脱离**。
- 还可能在丢弃次要或其他有效载荷之前搜索VME工件，并在自动发现过程中使用规避过程中获得的信息来**塑造后续行为**。
- 攻击者可以通过**搜索安全监视工具**（例如Sysinternals，Wireshark等）来使用包括安全软件发现在内的多种方法来完成虚拟化/沙盒逃避，以帮助确定其是否为分析环境。
- 其他方法包括在恶意软件代码中使用睡眠计时器或循环，以避免在临时沙箱中进行操作。
  
## 利用场景
- **VME Artifacts工件发现**
  - 使用Windows Management Instrumentation，PowerShell，Systeminfo和Query Registry之类的实用程序来获取系统信息并搜索VME工件。
  - 在内存，进程，文件系统和/或注册表中搜索VME工件。
  - 合并为一个检查脚本，然后在确定系统为虚拟环境时退出程序。
  - 在VMWare之类的应用程序中，对手可以使用特殊的I / O端口发送命令并接收输出。
  - 检查驱动器的大小。如使用Win32 DeviceIOControl函数。
  - 注册表中的VME工件示例
   `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`
    `HKLM\HARDWARE\Description\System\"SystemBiosVersion";"VMWARE"`
    `HKLM\HARDWARE\ACPI\DSDT\BOX_`
  - 系统上的示例VME文件和DLL [2]
   `WINDOWS\system32\drivers\vmmouse.sys`
   `WINDOWS\system32\vboxhook.dll`
   `Windows\system32\vboxdisp.dll`
  - 常规检查可能枚举这些应用程序所独有的正在运行的服务，系统上已安装的程序，与虚拟机应用程序有关的字符串的制造商/产品字段以及特定于VME的硬件/处理器指令。
- **用户活动发现**
  - 在主机上搜索用户活动（如浏览器历史记录，缓存，书签，主目录中的文件数等），以确保真实环境的安全。
  - 通过用户交互和数字签名等方式来检测此类信息。
  - 让恶意软件检查鼠标单击的速度和频率，以确定是否是沙盒环境。
  - 依赖于特定的用户与系统的交互，如在激活宏之前等待文档关闭，等待用户双击嵌入式图像以激活等。
- **虚拟硬件指纹发现**
  - 检查系统的风扇和温度，以收集可以指示虚拟环境的证据。
  - 使用WMI查询执行CPU检查`$q = "Select * from Win32_Fan" Get-WmiObject -Query $q`。如果结果返回的元素多于零，则该机器是一台物理机器。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 虚拟化、沙箱和相关的发现技术可能会在操作的第一步中出现，但也可能会在对手了解环境的整个过程中出现。
- 根据获得的信息，将数据和事件视为可能导致其他活动（如横向运动）的**行为链**的一部分。
- 监视生成的短时间内，收集各种系统信息，或执行其他形式的发现的**可疑进程**。

***

### Web Service (网络服务)(All)
>[原文链接](https://attack.mitre.org/techniques/T1102/)
同第十部分“Command And Control”
## 背景
- 攻击者可以使用现有的合法外部Web服务作为将命令中继到受感染系统的手段。

## 利用场景
- 这些命令还可以包括指向命令和控制（C2）基础结构的指针。
- 对手可能会在死点解析器dead drop resolver（嵌入（通常是模糊/编码）域或IP地址的Web服务）上发布内容。被感染主机与服务器联系并被解析器重定向。
- 流行网站和社交媒体可能会给C2机制提供大量的**掩护**，因为网络中的主机可能已经在协商前与它们进行了通信。使用如Google或Twitter提供的公共服务，攻击者更容易隐藏在预期的噪音中。
- Web服务提供商通常使用SSL/TLS加密，为对手提供**额外的保护级别**。
- 使用Web服务还可以通过恶意软件二进制分析保护后端C2基础设施不被发现，同时还可以启用操作**弹性**（因为该基础设施可能会动态更改）。

## 防御方式
缓解|描述
:--:|:--
网络入侵防护|使用网络签名识别特定恶意软件流量，使用网络入侵检测和防御系统缓解网络级别的活动。
限制基于Web的内容|Web代理可用于实施外部网络通信策略，以防止使用未经授权的外部服务。
## 检测
- 使用网络连接来**关联**未知或可疑过程活动的主机数据。
- 如果数据已加密，则数据包捕获分析将需要**SSL/TLS检查**。
- 分析网络数据中**不常见的数据流**（例如客户端发送的数据明显多于从服务器接收的数据）。
- **用户行为监视**有助于检测异常活动模式。
- **分析数据包内容**以检测未遵循所使用端口的预期协议行为的通信

***

### XSL Script Processing(XSL脚本处理)(Windows)
>[原文链接](https://attack.mitre.org/techniques/T1220/)

同第二部分“Execution”
***

***

## Credential Access (凭证访问)

>攻击者试图窃取账户和密码。


**凭证访问**包括用于窃取登录凭据（如帐户名和密码）的技术。获取凭据的技术包括**密钥记录**和**凭证转储**。使用合法凭证的访问更难被发现，并可能给攻击者提供**创建更多帐户**的机会。

***

### Account Manipulation(账户操作)(All)
>[原文链接](https://attack.mitre.org/techniques/T1098/)

同第三部分“Persistence”

***

### Bash History(Bash历史)(Linux&macOS)
>[原文链接](https://attack.mitre.org/techniques/T1139/)

## 背景
- Bash使用`history`跟踪用户在命令行上键入的命令。用户注销后，历史记录将刷新到用户的.bash_history文件中。
- 对于每个用户，此文件位于相同的位置：`~/.bash_history`。通常，此文件跟踪用户的最后500个命令。

## 利用场景
- 用户通常在命令行上输入用户名和密码作为程序的参数，然后在注销时将其保存到此文件中,攻击者可以通过在文件中查找潜在的凭据来滥用此功能。

## 防御方式
缓解|描述
:--:|:--
操作系统配置|防止用户的命令历史记录刷新到他们的`.bash_history`文件，包括使用以下命令的多种方法：`set +o history`并`set -o history`开启再次登录; 添加`unset HISTFILE`到用户的`.bash_rc`文件中；使用写命令`ln -s /dev/null ~/.bash_history`到`/dev/null`代替。

## 检测
- 监视`.bash_history`**读取用户的时间**，可以帮助提醒可疑活动。- 监视**行为**，用户经常通过`history`而不是`cat ~/.bash_history`来访问历史记录。

***

### Brute Force	(暴力破解)(All)
>[原文链接](https://attack.mitre.org/techniques/T1110/)
## 背景
- 当密码未知或获得密码哈希时，对手可能会使用蛮力尝试访问帐户。

## 利用场景
- 系统地**计算散列**的密码的技术是可用的，或者对手可以使用预先计算的**彩虹表**来破解散列。通常在目标网络之外的敌方控制系统上完成。
- 在不知道密码或散列的情况下**暴力破解**或尝试已知或可能的密码来**字典攻击**。这是一个风险更大的选项，取决于登录失败策略可能会导致身份验证失败和帐户锁定。
- 一种相关的技术称为**密码喷涂（枚举用户）**password spraying，即使用一个可能是一个常用的密码的密码，或小密码列表（与域的复杂性策略相匹配）。尝试使用该密码和网络上的不同帐户进行登录，以避免使用多个密码强制单个帐户时通常会发生的帐户锁定。
  - 通常，在进行密码喷涂时，会针对如下常用端口上的管理服务
  - SSH (22/TCP)
  - Telnet (23/TCP)
  - FTP (21/TCP)
  - NetBIOS / SMB / Samba (139/TCP & 445/TCP)
  - LDAP (389/TCP)
  - Kerberos (88/TCP)
  - RDP/Terminal Services (3389/TCP)
  - HTTP/HTTP Management Services (80/TCP & 443/TCP)
  - MSSQL (1433/TCP)
  - Oracle (1521/TCP)
  - MySQL (3306/TCP)
  - VNC (5900/TCP)
- 除了管理服务之外，攻击者还会攻击单点登录SSO和云上应用，以及面向外部的电子邮件应用程序如Office365。
  
## 防御方式
缓解|描述
:--:|:--
帐户使用策略|在一定数量的登录失败尝试之后设置**帐户锁定策略**以防止猜测密码。过于严格的策略可能会导致DOS，使暴力破解中使用的所有帐户均无法使用。
多因素认证|使用**多因素身份验证**。尽可能在面向外部的服务上启用多因素身份验证。
密码策略|创建密码策略时参考**[NIST准则](https://pages.nist.gov/800-63-3/sp800-63b.html)**。

## 检测
- 哈希爆破通常在目标网络范围之外进行，因此很难检测哈希何时被破解。
- 监视**身份验证日志**，如果身份验证失败率很高，可能系统被攻击者暴力破解。
- 监视**跨多个帐户的失败的身份验证尝试**，这些尝试可能是由于密码喷涂尝试导致的。
- 域控制器DC: `Audit Logon` (Success & Failure) for `event ID 4625`.
- 域控制器DC: : `Audit Kerberos Authentication Service` (Success & Failure) for `event ID 4771`.
- 所有系统: `Audit Logon` (Success & Failure) for `event ID 4648`.
- 在默认环境中，LDAP和Kerberos连接尝试不太可能通过SMB触发事件， 

***

### Credential Dumping (凭证转储) (All)
>[原文链接](https://attack.mitre.org/techniques/T1003/)
## 背景
- 凭据转储是从操作系统和软件**获取**帐户登录名和密码信息的过程（通常以哈希或明文密码的形式）。
- 之后可以使用凭证执行**横向移动**并**访问**受限制的信息。

## 利用场景
- **Windows**
  - **SAM** (Security Accounts Manager)
    - SAM是一个**数据库文件**，其中包含主机的本地帐户。通常使用`net user`命令搜索。
    - 要枚举SAM数据库，需要**system级别**的访问。
    - 可使用多种工具通过内存中（in-memory）技术来检索SAM文件。
    pwdumpx.exe
    gsecdump
    Mimikatz
    secretsdump.py
    - 可以使用Reg从注册表中提取SAM ：
    `reg save HKLM\sam sam`
    `reg save HKLM\system system`
    - 然后可以使用Creddump7在本地处理SAM数据库以检索哈希。
    - Rid 500是本地内置管理员。
    - Rid 501是来宾帐户。
    - RID 1,000+是用户帐户。
  - **缓存的凭证**(Cached Credentials)
    - 当域控制器不可用时，由Windows Vista和更新版本的缓存凭据使用的DCC2（域缓存凭据版本2）哈希。
    - 默认缓存凭据的数目会有所不同，并且每个系统都可以更改此数目。
    - 此哈希不允许传递哈希类型的攻击。
    - 可以使用许多工具通过内存技术**检索SAM文件**。
    pwdumpx.exe
    gsecdump
    Mimikatz
    - 可以使用reg.exe从注册表中提取文件，并使用Creddump7收集凭据。
    - Windows Vista的缓存凭据是使用PBKDF2派生的。
  - **LSA Secrets** (Local Security Authority)
    - 通过对主机的SYSTEM访问，LSA Secrets通常允许从本地帐户到基于域的帐户凭据的简单访问。。
    - **注册表**用于存储LSA Secrets。在本地或域用户的上下文中运行服务时，其密码将存储在注册表中。如果启用了自动登录，则此信息也将存储在注册表中。
    - 可以使用多种工具通过内存技术来**检索SAM文件**。
    pwdumpx.exe
    gsecdump
    Mimikatz
    secretsdump.py
    - 可以使用reg.exe从注册表中提取文件，并使用Creddump7收集凭据。
    - 注：该机制提取的密码是UTF-16编码的，这意味着它们以明文形式返回
    - 注：Windows 10增加了对LSA机密的保护。
  - **域控制器的NTDS** (NTDS from Domain Controller)
    - 活动目录Active Directory存储有关域成员的信息，包括用于验证凭据和定义访问权限的设备和用户。
    - 活动目录域数据库存储在`NTDS.dit`文件中。默认情况下，NTDS文件将位于域控制器的`%SystemRoot%\NTDS\NTDS.dit`中。
    - 以下工具和技术可用于枚举NTDS文件和整个Active Directory散列的内容。
    Volume Shadow Copy
    secretsdump.py
    Using the in-built Windows tool, ntdsutil.exe
    Invoke-NinjaCopy 
  - **GPP组策略首选项文件** (NTDS from Domain Controller)
    - 组策略首选项（GPP）是允许管理员使用嵌入凭据创建域策略的工具。这些策略允许管理员设置本地帐户。
    - 这些组策略存储在域控制器上的SYSVOL中，这意味着任何域用户都可以查看SYSVOL共享并解密密码（AES私钥在线泄漏）。
    - 以下工具和脚本可用于从**组策略首选项XML文件**收集和解密密码文件：
    Metasploit的后期开发模块：`post/windows/gather/credentials/gpp`
    Get-GPPPassword [5]
    gpprefdecrypt.py 
    - 注：在SYSVOL共享上，以下内容可用于枚举潜在的XML文件。`dir /s * .xml`
  - **服务主体名称SPNs** (Service Principal Names)
    - 参考[Kerberoasting](https://attack.mitre.org/techniques/T1208/)
  - **明文凭证** (Plaintext Credentials)
    - 用户登录到系统后，会生成各种凭据，并将其存储在内存中的本地安全授权子系统服务（LSASS）进程中。管理用户或系统可以获取这些凭据。
    - **SSPI**安全支持提供程序接口作为多个SSPs（安全支持提供程序）的公共接口，作为一个动态链接库DLL可以被一或多个SSPs使用。
    - 以下**SSP**可用于访问凭据：
    Msv：交互式登录、批量登录和服务登录通过Msv身份验证包完成。
    Wdigest：摘要身份验证协议设计用于超文本传输协议HTTP，和简单身份验证安全层SASL交换。
    Kerberos：在Windows 2000和更高版本中，首选用于相互客户端-服务器域身份验证。
    CredSSP：为远程桌面服务提供SSO和网络级别的身份验证。
    - 以下工具可用于枚举凭据：
    Windows Credential Editor
    Mimikatz
    - 与内存技术一样，LSASS进程内存也可以从目标主机中转储并在本地系统上进行分析。
    例如，在目标主机上使用procdump：`procdump -ma lsass.exe lsass_dump`
    在本地，可以运行mimikatz：
    `sekurlsa::Minidump lsassdump.dmp`
    `sekurlsa::logonPasswords`
  - **DCSync**
    - DCSync是凭证转储的**变体**，可用于从域控制器获取敏感信息。
    - 该操作不执行可识别的恶意代码，而是通过滥用域控制器的**API**来模拟来自远程域控制器的复制过程。
    - 域控制器上的管理员、域管理员、企业管理组或计算机帐户的任何成员都可以运行DCSync从Active Directory中提取密码数据，其中可能包括KRBTGT和Administrators等潜在有用帐户的当前和历史哈希值
    - 这些散列可以用于创建一个Golden Ticket，用于传递凭据或更改帐户的密码。
    - DCSync功能已包含在Mimikatz的`lsadump`模块中。
    - Lsadump还包括NetSync，通过传统复制协议执行DCSync。
- **Linux**
  - **Proc filesystem**
    - Linux上的`/proc`**文件系统**包含大量有关正在运行的操作系统状态的信息。
    - 以root用户权限运行的进程可以使用此功能镜像其他正在运行的程序的实时内存。
    - 如果这些程序中的任何一个将密码存储在明文或内存中的密码散列中，则可以分别为使用或暴力攻击获取这些值。
    - 使用MimiPenguin（受Mimikatz启发的开源工具）工具转储进程内存，然后通过查找文本字符串和regex模式来获取密码和散列，以了解给定的应用程序（如Gnome Keyring、sshd、Apache）身份验证工件如何使用内存来存储。

## 防御方式
缓解|描述
:--:|:--
Active Directory配置|恰当配置`Replicating Directory Changes`（复制目录更改）的访问控制列表以及与域控制器复制相关的其他权限。
凭证访问保护|在Windows 10中，Microsoft实现了`Credential Guard`以保护LSA secrets。默认情况下为未配置状态，且具有硬件和固件系统要求。但不能防止所有形式的凭证转储。
操作系统配置|考虑禁用或限制NTLM。
密码策略|确保本地管理员帐户在网络所有系统上都具有复杂的唯一密码。
特权账户管理(Windows)|除非用户或管理域帐户已进行严格控制，不要将它们放在整个系统的本地管理员组中，（通常等效于在所有系统上使用具有相同密码的本地管理员帐户）。遵循最佳实践来设计和管理企业网络，限制特权帐户在各个管理层之间的使用。
特权账户管理(Linux)|从内存中镜像密码需要root特权。遵循最佳实践，限制对特权帐户的访问。
特权流程完整性|在Windows 8.1和Windows Server 2012 R2上，启用LSA的`Protected Process Light`。
用户培训|培训用户和管理员不要对多个帐户使用相同的密码，限制帐户和系统之间的凭证重叠。

## 检测
- **Windows**
  - 监视**与lsass.exe交互的意外进程**。
    - 常见凭据转储程序（如Mimikatz）通过打开该进程、查找LSA机密密钥和解密存储凭据详细信息的内存部分来访问LSA子系统服务（lsass）进程。
    - 凭证转储程序还可以使用反射进程注入的方法来减少恶意活动的潜在特征。
  - 监视**散列行为**。
    - 散列转储程序打开本地文件系统（`SystemRoot%/system32/config/SAM`）上的安全帐户管理器（SAM），或创建注册表SAM项的转储以访问存储的帐户密码散列。
    - 一些散列转储程序将本地文件系统作为设备打开，并解析到SAM表，以避免文件访问防御。其他人会在读取散列之前制作一个SAM表的内存副本。
  - 监视可能已被控制账户的使用。
  - 在Windows 8.1和Windows Server 2012 R2上，监视创建`LSASS.exe`的**Windows日志**，确认LSASS是作为受保护进程启动的。
  - 监视程序执行的**进程和命令行参数**。
    - 包含内置特性，或合并现有的工具，如Mimikatz。
    - 包含证书销毁功能的POWER Script脚本，如PosisPrimIT的调用MIMIKATZ模块。
    - 可能需要在操作系统中配置附加的日志记录特征来收集必要的分析信息。
  - 监视**域控制器日志**，查看复制请求和其他可能与DCSync关联的未计划活动。
    - 注意：域控制器不能记录来自默认域控制器帐户的复制请求。
  - 监视来自**与已知域控制器无关**的IP的网络协议和其他复制请求。
- **Linux**
  - **行为**。要获取存储在内存中的密码和散列，进程必须在`/proc`文件系统中为要分析的进程打开一个映射文件。此文件存储在`/proc//maps`路径下，其中的目录是要查询此类身份验证数据的程序的唯一pid。
  - **AuditD监视工具**。可以用来监视在proc文件系统中打开此文件的恶意进程，告警此类程序pid、进程名和参数。

***

### Credentials from Web Browsers(Web浏览器凭证)(All)
>[原文链接](https://attack.mitre.org/techniques/T1503/)
## 背景
- 攻击者可以通过读取特定于目标浏览器的文件,来从Web浏览器获取凭据。
- Web浏览器通常会保存凭据如网站用户名和密码，以便无需手动输入。
- Web浏览器通常将凭据以加密格式存储在**凭据存储区**中，存在从Web浏览器中提取纯文本凭据的方法。

## 利用场景
- Windows系统上，通过**读取数据库文件**`AppData\Local\Google\Chrome\User Data\Default\Login Data`并执行SQL查询`SELECT action_url, username_value, password_value FROM logins;`从`Google Chrome`获得加密的凭据。然后，通过将加密的凭据传递给Windows API函数`CryptUnprotectData`获取纯文本密码，
- 攻击者还可以通过在Web浏览器进程内存中**搜索**与凭据匹配的模式来获取凭据。
- 从网络浏览器获取凭据后，可以尝试在不同系统和/或帐户之间**回收凭据**，以扩大访问范围。如果凭据是特权帐户，可以大大提高对手的目标。

## 防御方式
缓解|描述
:--:|:--
密码策略|权衡将凭据存储在Web浏览器中的风险。如果Web浏览器凭据公开非常重要，则可以使用技术控制/策略/用户培训来防止凭据存储在Web浏览器中。

## 检测
- **确定**包含凭据的网络浏览器**文件**，例如Google Chrome的Login Data数据库文件：`AppData\Local\Google\Chrome\User Data\Default\Login Data`。
- 监视包含凭据的Web浏览器文件的文件**读取事件**，尤其是在读取过程与主题Web浏览器无关时。
- 监视进程执行日志，`PowerShell Transcription`，重点关注那些执行多种行为，如读取Web浏览器进程内存，利用正则表达式，并包含许多常见Web应用程序（Gmail，Twitter，Office365等）关键字的行为。

***

### Credentials in Files (文件中的凭证) (All)
>[原文链接](https://attack.mitre.org/techniques/T1081/)
## 背景
- 用户创建的用于存储自己凭据的文件
- 用于组的共享凭据存储
- 包含系统或服务密码的配置文件
- 包含嵌入式密码的源代码/二进制文件。

## 利用场景
- 攻击者可能会在本地文件系统和远程文件共享中搜索**包含密码的文件**。
- 可以通过凭据转储从备份或保存的**虚拟机**中提取密码。
- 也可以从Windows**域控制器**上存储的组策略首选项中获取密码。
- 经过身份验证的用户凭据通常存储在**本地配置和凭据文件**中（多见于云环境）。在某些情况下，可以将这些文件复制并在另一台机器上重复使用，或者可以读取内容，无需复制文件将其用于身份验证。

## 防御方式
缓解|描述
:--:|:--
Active Directory配置|删除易受攻击的组策略首选项。
审计|搜索包含密码的文件，并采取措施降低发现风险。
密码策略|建立禁止在文件中存储密码的组织策略。
文件和目录权限配置|将文件共享限制为特定目录，仅必要的用户具有访问权限。
用户培训|确保开发人员和系统管理员了解在在终端系统或服务器上使用明文密码的相关风险。

## 检测
- 监视执行进程的**命令行参数**，查找可能指示搜索密码的可疑单词或正则表达式（如：password、pwd、login、secure、credentials）。

***

### Credentials in Registry (注册表中的凭证) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1214/)
## 背景
- Windows**注册表**存储系统或其他程序可以使用的配置信息。攻击者可以查询注册表，以查找已存储供其他程序或服务使用的凭据和密码。

## 利用场景
- 查找与密码信息相关的注册表项的示例命令：
  本地机器配置单元：`reg query HKLM /f password /t REG_SZ /s`
  当前用户配置单元：`reg query HKCU /f password /t REG_SZ /s`

## 防御方式
缓解|描述
:--:|:--
审计|在注册表中搜索凭据，并进行相应管理。
密码策略|不将凭据存储在注册表中。
特权账户管理|如果有软件必须将凭据存储在注册表中，则确保关联账户遵循最小权限原则。

## 检测
- 监视可用于**查询注册表**（如Reg）的应用程序的进程，并收集可能指示正在搜索凭据的命令参数。
- 将活动与相关的可疑行为**关联**分析。这些行为可能表明存在活动入侵，以减少误报。

***

### Exploitation for Credential Access (凭证访问利用) (All)
>[原文链接](https://attack.mitre.org/techniques/T1212/)
## 背景
- 当攻击者利用程序，服务或操作系统软件或内核本身内的**不安全编程**来执行攻击者控制的代码时，就会利用软件漏洞。


## 利用场景
- 认证和身份验证机制可能会被对手利用，作为**获取可用证书**或**绕过**进程获取系统访问权限的手段。
- 对凭证访问的利用还可能导致**特权升级**，取决于漏洞利用过程或获取的凭据。
- 示例：[MS14-068](https://www.freebuf.com/vuls/56081.html)。针对Kerberos，可用于使用域用户权限伪造Kerberos凭据。

## 防御方式
缓解|描述
:--:|:--
应用程序隔离和沙箱|通过使用沙箱利用未发现或未修补的漏洞。其他类型的虚拟化和应用程序微分段也可以减轻某些类型的利用的影响。
漏洞利用防护|使用安全应用程序来缓解某些攻击行为，如Windows Defender Exploit Guard（WDEG）和增强的缓解体验工具包（EMET）。也可以尝试控制流完整性检查。
威胁情报|强大的网络威胁情报能力可以确定哪些类型和级别的威胁可能使用软件攻击和特定组织的0day攻击。
软件更新|企业内部终端和服务器定期更新软件。

## 检测
- **行为**。
  - 程序**运行**异常、不稳定或崩溃；
  - **进程**的异常行为；
  - **账户**的不正常使用或未知账户的使用。

***

### Forced Authentication (强制认证) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1187/)
## 背景
- 服务器消息块**SMB协议**通常在Windows网络中用于身份验证和系统之间的通信，以访问资源和文件共享。
- Windows系统尝试连接到SMB资源时，将**自动尝试身份验证**并将当前用户的**凭据信息发送到远程系统**。此行为在企业环境中很常见，让用户不需要输入凭据即可访问网络资源。
- 当SMB被阻止或失败时，Windows系统通常将Web分布式创作和版本控制**WebDAV**用作备份协议。WebDAV是HTTP的扩展，通常在TCP端口**80和443**上运行。

## 利用场景
- 利用此行为通过强制SMB身份验证来访问用户**帐户哈希**。
- 通过网络钓鱼，向用户发送包含指向外部服务器的资源链接（即模板注入）的附件，或将文件放在特权帐户的导航路径（如桌面上的SCF文件）上，或放在受害者要访问的可公开访问的共享上。当用户的系统访问不受信任的资源时，它将尝试进行身份验证，并通过SMB将包括用户哈希凭据在内的信息**发送到对手控制的服务器**。
- 通过访问凭证散列，可以通过离线暴力破解以获得明文凭证。
- 常见恶意附件形式
  - 一个speraphishing附件，其中包含一个具有在打开时自动加载的资源（即模板注入）的文档。如包含类似于`file[：]//[远程地址]/Normal.dotm`的请求来触发SMB请求。
  - 一个经过修改的.LNK或.SCF文件，其图标文件名指向外部引用，如`\[remote address]\pic.png`，当图标文件重复收集凭据时，该文件将强制系统加载资源。

## 防御方式
缓解|描述
:--:|:--
过滤网络流量|通过出口过滤或阻止TCP端口139、445和UDP端口137，以阻止SMB流量从企业网络发往外部；筛选或阻止WebDAV协议流量发送出网络；如果需要通过SMB和WebDAV访问外部资源，则使用白名单严格限制。
密码策略|通过使用强密码，增加破解密码哈希的难度。

## 检测
- 监视TCP**端口**139、445和UDP端口137上的SMB**通信**，以及试图与外部未知系统建立连接的WebDAV通信。
- 对于内部流量，监控工作站到工作站的**异常SMB流量**（与基线相比）。对于许多网络来说不应有该类通信。
- 监视系统和虚拟环境中的**指向外部网络资源的**资源的.LNK，.SCF或任何其他文件的创建和修改。

***

### Hooking (钩子进程) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1179/)

同第三部分“Persistence”，第四部分“Privilege Escalation”

***

### Input Capture (输入捕获) (All)
>[原文链接](https://attack.mitre.org/techniques/T1056/)
## 背景
- 攻击者可以使用**捕获用户输入**的方法来获取有效帐户和信息收集的凭据，包括键盘记录和输入字段拦截。

## 利用场景
- **键盘记录**是最流行的输入捕获类型，具有多种截取键盘的方法，但也存在其他方法将信息用于特定目的，如执行UAC提示或包装Windows默认凭据提供程序。
- 当凭证转储Credential Dumping无效时，按键记录可用于获取新访问机会的凭据，并且可能在机会出现之前在系统上保持**被动静默记录**一段时间。
- 对手还可以在**外部门户**界面上安装代码（如VPN登录页面），以捕获和传输试图登录到该服务的用户的凭据。
- 输入捕获可以在**攻陷后进行**，并使用合法的管理访问作为备份措施，通过外部远程服务External Remote Services和有效帐户Valid Accounts保持网络访问，或作为利用外部web服务进行初始利用的一部分。

## 防御方式
缓解|描述
:--:|:--
软件|使用各类安全工具检测软件类键盘记录器。
硬件|检查设备接口，并使用安全工具检测硬件类键盘记录器。
web门户|检查源码是否存在可被利用的漏洞。

## 检测
- 键盘记录程序可以采用多种形式，可能涉及**修改注册表**和**安装驱动程序**，**设置挂钩**或**轮询**以拦截键盘输入。常用的API调用包括`SetWindowsHook`，`GetKeyState`和`GetAsyncKeyState`。
- 监视注册表和文件系统中的此类**更改**并检测**驱动程序安装**，以及查找常见的键盘记录**API调用**。单独的API调用并不表示按键记录，但可以提供行为数据与其他信息（例如，写入磁盘的新文件和异常进程）**关联**。
- 监视**注册表**添加自定义凭据提供程序的活动。
- 检测**正在使用的受害有效帐户**。

***

### Input Prompt (输入提示) (All)
>[原文链接](https://attack.mitre.org/techniques/T1141/)
## 背景
- 当执行的程序需要比当前用户上下文中的权限更多的权限时，操作系统通常会**提示**用户提供适当的凭据，以授权为该任务提升的权限

## 利用场景
- 对手可能会**模仿**此功能，以一个看似合法的提示提示用户凭据，如需要额外访问的假安装程序或假恶意软件删除套件，诱导用户进行下一步认证。
- 此类型的提示可用于通过**各种语言**（如AppleScript）收集凭据和PowerShell

## 防御方式
缓解|描述
:--:|:--
用户培训|提高安全意识并提高对潜在恶意事件的怀疑（如提示凭据的Office文档）。

## 检测
- 监视进程执行过程中是否存在异常程序以及可用于提示用户输入凭据的**恶意脚本**。
- 检查并仔细检查输入提示中是否存在**非法指标**，例如非传统标语，文本，时间和来源。

***

### Kerberoasting (kerberoasting攻击 (Windows))
>[原文链接](https://attack.mitre.org/techniques/T1208/)
## 背景
- 服务主体名称**SPN**用于唯一标识Windows服务的每个实例。
- 要启用身份验证，**Kerberos**要求spn至少与一个服务登录帐户（专门负责运行服务的帐户）关联。

## 利用场景
- 拥有有效Kerberos票证授予票证TGT的对手，可以从域控制器DC为任何SPN**请求**一个或多个Kerberos票证授予服务(TGS)票证。
- 这些票证的一部分可能用**RC4**算法（或其他不安全的加密算法）加密，则说明与SPN关联的服务帐户的`Kerberos 5 TGS-REP etype 23`哈希被用作私钥，容易被脱机暴力破解。
- 可以利用从网络流量**捕获**的服务票证执行相同的攻击。
- 被破解的散列可以通过访问**有效帐户**来实现**持久性**、**权限提升**和**横向移动**。

## 防御方式
缓解|描述
:--:|:--
加密敏感信息|启用AES Kerberos加密或其他更强的加密算法，不使用RC4。
密码策略|确保服务帐户的密码长度和复杂性，密码定时过期。考虑使用如密码库的，组托管服务帐户或其他第三方产品。
特权账户管理|服务账户权限最小化，包括特权组（例如域管理员）的成员资格。

## 检测
- 启用**审核Kerberos服务**票证操作，记录Kerberos TGS服务票证请求。
- 监视**异常活动**，如在短时间内提出大量请求的帐户。
- **系统日志**。Event ID 4769，尤其是还请求了RC4加密`Type 0x17`。

***

### Keychain (Apple 钥匙串) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1142/)
## 背景
- Keychain是macOS的**密码管理系统**。跟踪用户密码和凭据的内置方式，用于许多服务和功能，如WiFi密码、网站、安全注释、证书和Kerberos。
- Keychain文件位于`~/Library/Keychains/`,`/Library/Keychains/`和`/Network/Library/Keychains/`。
- 默认情况下，macOS中内置的`security`命令行程序提供了管理这些凭据的有用方法。
- 要管理其凭据，用户必须使用**其他凭据**来访问Keychain。

## 利用场景
- 如果获取登录Keychain的凭据，则他们可以**访问**存储在此Vault中的所有其他凭据。
- 默认情况下，Keychain的密码短语是用户的登录凭据。

## 防御方式
缓解|描述
:--:|:--
密码策略|更改用户的登录Keychain的密码为强密码。

## 检测
- 监视**对Keychain的系统调用**以确定是否存在可疑访问活动。
- 解锁Keychain并从中使用密码是一个非常常见的过程，任何检测技术都可能会产生很多误报。

***

### LLMNR/NBT-NS Poisoning and Relay (LLMNR/NBT-NS中毒和中继) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1171/)
## 背景
- 链路本地多播名称解析LLMNR，NetBIOS名称服务NBT-NS，是作为主机标识的替代方法的Microsoft Windows组件。
- **LLMNR**基于DNS格式，允许同一本地链接上的主机为其他主机执行名称解析。
- **NBT-NS**通过NetBIOS名称标识本地网络上的系统。

## 利用场景
- 通过响应LLMNR（UDP 5355）/NBT-NS（UDP 137）通信，来**欺骗**受害者网络上的权威源DNS，从而进行**DNS毒化**，使受害者与攻击者控制的系统通信。
- 如果请求的主机属于需要标识身份或身份验证的资源，则发送用户名和NTLMv2哈希。然后，攻击者可以通过监视端口流量或网络嗅探，收集通发送的散列信息，并通过蛮力离线破解散列以**获取明文密码**。
- 如果攻击者可以访问系统之间的身份验证路径中的系统，或当使用凭据的自动扫描向攻击者控制的系统进行身份验证时，可以**截获并中继**NTLMv2散列，以访问和执行针对目标系统的代码。
- 中继步骤可能与中毒同时发生，但也可能与中毒无关。

## 防御方式
缓解|描述
:--:|:--
禁用或删除功能或程序|如果环境中不需要LLMNR和NetBIOS，则在本地计算机安全设置中或通过组策略禁用它们。
过滤网络流量|使用基于主机的安全软件阻止LLMNR/NetBIOS通信。启用S​​MB签名以阻止NTLMv2中继攻击。

## 检测
- 监视`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`中`EnableMulticast`DWORD值的**更改**。0表示LLMNR被禁用。
- 如果安全策略禁用了LLMNR / NetBIOS，监视UDP 5355和UDP 137**端口通信**。
- 部署LLMNR/NBT-NS**欺骗检测工具**。监
- 监视Windows事件**日志**中Event ID 4697和7045检测成功的中继活动。

***

### Network Sniffing (网络嗅探) (All)
>[原文链接](https://attack.mitre.org/techniques/T1040/)
## 背景
- 网络嗅探是指使用系统上的网络接口**监视或捕获**通过有线或无线连接发送的信息。

## 利用场景
- 攻击者可以将网络接口设置为混杂模式，以**被动**地嗅探通过网络传输的数据，也可以使用跨接端口来**捕获**大量数据。
- 通过此技术捕获的数据可能包括**用户凭据**，特别是通过不安全、未加密协议发送的凭据。
- 通过DNS中毒的技术，可以通过**重定向**来捕获网站、代理和内部系统的凭证。
- 网络嗅探还可以侦查**配置细节**，如运行的服务、版本号和其他网络特征（P地址、主机名、VLAN ID），这些都是后续横向移动和/或防御规避活动所必需的。

## 防御方式
缓解|描述
:--:|:--
加密敏感信息|确保所有有线和无线流量均已正确加密。对认证协议如Kerberos使用最佳实践，并确保可能包含凭据的Web流量受到SSL/ TLS的保护。
多因素认证|尽可能使用多因素身份验证。

## 检测
- 检测导致嗅探网络流量的**事件**，如中间人攻击。
- 监视**ARP**欺骗和可疑ARP广播。
- 检测网络中的**脆弱性**。
- 检测恶意**配置更改和设备映像**。

***

### Password Filter DLL (密码筛选DLL) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1174/)
## 背景
- **password filters** 是Windows密码政策执行机制，适用于域和本地帐户。
- Filters作为动态链接库**DLL**实现，其中包括对密码策略有效的潜在验证密码。D​​LL可以位于本地计算机上的本地帐户或域控制器的域帐户中。
- 将新密码注册到**SAM**(Security Accounts Manager)之前，**LSA**(Local Security Authority)对每一个注册的Filter进行认证，都确认有效之前任何潜在的更改都不会生效。。

## 利用场景
- 攻击者可以注册**恶意Password Filter**，以从本地计算机和/或整个域中获取凭据。
- 要执行正确的验证，Filter必须从LSA接收纯文本凭据。恶意Password Filter将在每次发出密码请求时接收这些纯文本凭据。

## 防御方式
缓解|描述
:--:|:--
操作系统配置|确保仅注册有效的Password Filter。D​​LL必须存在于域控制器或本地计算机的Windows安装目录，默认`C:\Windows\System32\`中，并在其中具有相应的条目`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`。

## 检测
- 监视与陌生Password Filter之间的**更改**。
  - 新安装的Password Filter在系统重新启动后才会生效。
  - 密码过滤器将显示为自动运行并在lsass.exe中加载DLL。

***

### Private Keys (私钥) (All)
>[原文链接](https://attack.mitre.org/techniques/T1145/)
## 背景
- 私钥和证书用于身份验证，加密/解密和数字签名。

## 利用场景
- 从已攻陷的系统中**收集私钥**，用于对SSH等远程服务进行身份验证，或用于解密其他收集的文件如电子邮件。
- 通用密钥和证书文件扩展名包括：.key、.pgp、.gpg、.ppk、.p12、.pem、.pfx、.cer、.p7b、.asc。
- 还可以在**公共密钥目录**中查找，如使用`~/.ssh`在基于*nix的系统上查找ssh密钥，或在Windows上查找`C:\Users(username).ssh\`。
- 私钥可能需要密码或口令（passphrases）才能进行操作，因此攻击者通常结合输入捕获进行密钥记录，或者尝试脱机爆破口令。

## 防御方式
缓解|描述
:--:|:--
审计|只允许授权密钥定期访问关键资源，并审核访问列表。
加密敏感信息|将密钥存储在单独的加密硬件而非本地系统。
网络细分|使用单独的基础架构管理关键系统，防止凭据和权限在可用作横向移动的系统上重叠。
密码策略|对私钥使用强口令，使破解变得困难。
文件和目录权限|在包含敏感私钥的文件夹上正确设置权限防止意外访问。

## 检测
- 监视对与加密密钥和证书有关文件和**目录的访问**，作为收集和渗透活动的访问模式指标。
- 收集**身份验证日志**，查找表明不正确使用密钥或证书进行远程身份验证的异常活动。

***

### Securityd Memory (安全内存) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1167/)
## 背景
- 在El Capitan之前的OS X中，具有root访问权限的用户可以读取**纯文本已登录用户的密钥链密码**，因为Apple的密钥链实现允许缓存这些凭据以避免反复提示用户输入密码。
- Apple的安全实用程序获取用户的登录密码，并使用PBKDF2对其进行加密，然后将该主密钥**存储在内存中**。
- Apple还使用一组密钥和算法来加密用户密码，但是一旦找到主密钥，攻击者只需遍历其他值即可解锁最终密码。

## 利用场景
- 如果攻击者获得root访问权限（允许他们读取securityd的内存），则可以通过**内存扫描**，以相对**较少的尝试**找到正确的密钥序列，**解密**用户登录密钥链。
- 如果成功，攻击者将获得用户、WiFi、邮件、浏览器、证书、安全说明secure notes等**所有的明文密码**。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 监测疑似攻陷或新加入的设备中，对**内存读取和镜像**的异常尝试。

***

### Steal Web Session Cookie (Web会话Cookie窃取)
>[原文链接](https://attack.mitre.org/techniques/T1539/)
## 背景
- 用户对网站进行身份验证后，Web应用程序和服务通常将会话**cookie**用作身份验证令牌，来获取访问Web应用程序或Internet服务的权限，而无需凭据。
- Cookies通常在很长一段时间内有效。
- Cookies可以在磁盘、浏览器的进程内存和远程系统的网络通信中找到。
- 目标计算机上的其他应用程序可能会在内存中存储敏感的身份验证cookie，如向云服务进行身份验证的应用程序。


## 利用场景
- 从本地系统的web浏览器**盗取**cookie；
- 使用一些开源框架，如Evilginx 2和Mauraena，通过钓鱼进行**中间人攻击**收集会话cookie。
- 获取有效的Cookie后，可以使用Cookie盗用账号登录到相应的Web应用程序。
- 会话cookies可用于**绕过**某些**多因素身份验证**协议。


## 防御方式
缓解|描述
:--:|:--
多因素认证|通过多因素认证，如登录地点与秘钥结合进行认证
软件配置|配置浏览器或软件定时删除永久性cookie。
用户培训|培训用户以识别网络钓鱼。

## 检测
- 监视**访问**存储浏览器会话cookie的**本地文件**的尝试。
- 监视程序尝试**注入或镜像**浏览器进程内存的情况。

***

### Two-Factor Authentication Interception (双因素身份验证拦截) (All)
>[原文链接](https://attack.mitre.org/techniques/T1111/)
## 背景
- 使用**多因素身份验证**，和单独使用用户名和密码相比提供更高级别的安全性，但应意识到可用于拦截和绕过这些安全性机制的技术。
- 攻击者可以将身份验证机制（例如智能卡）作为目标，以获得对系统，服务和网络资源的访问权限。

## 利用场景
- 如果智能卡用于双因素身份验证（2FA），攻击者可以使用**键盘记录器**获取与智能卡关联的密码。
- 还可以使用密钥记录器以类似的方式瞄准其他**硬件令牌**，如RSA SecurID。捕获令牌输入，包括用户的个人识别码，可以提供**临时访问**（即在下一个值滚动之前重放一次性密码）以及可能使对手能够**预测**未来的身份验证码（给定对算法和用于生成附加的临时值的任何种子值的访问代码）。
- 2FA的其他方法可以被**截获**并被攻击者用于认证，如通过带外通信（电子邮件、短信）发送一次性代码。
- **复刻**硬件设备等方式。

## 防御方式
缓解|描述
:--:|:--
用户培训|安全意识培训。

## 检测
- 对键盘记录器等硬件、拦截等软件方式进行监测。

***


***

## Discovery (发现)
>攻击者试图更多的了解目标环境。

**发现**包括攻击者用来获取有关系统和内部网络知识的技术。这些技术可帮助对手在采取行动之前**观察环境**并**确定方向**。攻击者还可以**探索**他们可以控制的内容及切入点附近的内容，以发现如何**进一步利用**以达成目标。本机操作系统工具通常用于实现**信息收集**。

***


### Account Discovery (账户发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1087/)
## 背景
- 对手可能会尝试获取本地系统或域**帐户列表**。

## 利用场景
- **Windows**
  - 使用Net程序或dsquery命令`net user`、`net group`、`net localgroup`获取本地系统或域**帐户列表**。
  - 识别主要**用户**，当前登录的用户或通常使用系统的一组用户。
- **mac**
  - 使用`groups`和`id`命令枚举**组**。
  - 使用`dscl . list /Groups`和`dscacheutil -q group`命令枚举**组和用户**
  - 通过`/etc/master.passwd`文件枚举**本地账户**。
  - 通过`/etc/passwd`文件枚举**单用户**
- **Linux**
  - 使用`groups`和`id`命令枚举**组**。
  - 通过`/etc/passwd`文件枚举**本地账户**。
- **Office 365与Azure AD**
  - 通过身份验证的访问，可以使用多种工具来**查找帐户**。
  - 在`Get-MsolRoleMember`指定角色或权限组的情况下，可以使用PowerShell命令**获取帐户名**。
  - Azure CLI（AZ CLI）提供了一个界面，以获取对域进行身份验证访问的用户帐户。`az ad user list`将列出**域**中的所有**用户**。
  - `Get-GlobalAddressList`PowerShell命令可用于使用经过身份验证的会话，从域中获取**电子邮件地址和帐户**

## 防御方式
缓解|描述
:--:|:--
操作系统配置|防止在应用程序通过UAC提升时枚举管理员帐户。注册表项位于`HKLM\ SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators`。可以通过GPO将其禁用：`Computer Configuration > [Policies] > Administrative Templates > Windows Components > Credential User Interface: E numerate administrator accounts on elevation`。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他活动（如横向运动）的行为**关联分析**。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 还可以通过Windows**系统管理工具**（如Windows management Instrumentation和PowerShell）获取信息。

***

### Application Window Discovery (应用程序窗口发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1010/)
## 背景
- 对手可能会尝试获取打开的应用**程序窗口列表**。。

## 利用场景
- 窗口列表可以表现出有关**系统使用的信息**，也可以为键盘记录程序收集的信息**提供上下文**。
- 在Mac中，也可以使用小的AppleScript脚本完成。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他活动行为**关联分析**。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 还可以通过Windows**系统管理工具**（如Windows management Instrumentation和PowerShell）获取信息。

***

### Browser Bookmark Discovery (浏览器书签发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1087/)
## 背景
- 攻击者可能会枚举**浏览器书签**，以了解有关受感染主机的更多信息。
- 存储位置因平台和应用程序而异，通常存储在本地文件/数据库中。

## 利用场景
- 浏览器书签可能会显示有关用户的**个人信息**（如银行网站，兴趣，社交媒体等），以及有关**内部网络资源信息**（如服务器，工具/仪表盘或其他相关基础架构）。
- 攻击者访问有效凭据后，浏览器书签可以用来**提供其他目标**，尤其是凭据与浏览器缓存登录名关联的情况。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如收集和渗透。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
- 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
- 还可以通过Windows**系统管理工具**（如Windows management Instrumentation和PowerShell）获取信息。

***

### Domain Trust Discovery (域信任发现) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1087/)
## 背景
- 攻击者可能会尝试收集有关**域信任关系**的信息，这些信息可用于发现在复杂Windows域/森林环境中的横向移动机会。
- 域信任为域提供了一种机制，允许基于另一个域的身份验证过程访问资源。即允许**受信域**的用户访问受信任域中的**资源**。

## 利用场景
- 用于发现在复杂Windows域/森林环境中的横向移动机会。
- 现的信息可能有助于攻击者进行SID历史注入、传递票证和Kerberoasting。
- 可以使用`DSEnumerateDomainTrusts ()`Win32 API调用、.NET方法和LDAP枚举域信任。
- 已知Windows工具Nltest可以被武器化用于枚举域信任。

## 防御方式
缓解|描述
:--:|:--
审计|在现有域/森林中映射信任关系，并将信任关系保持在最低限度。
网络细分|对敏感域采用网络分段技术。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**。

***

### File and Directory Discovery (文件和目录发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1083/)
## 背景
- 攻击者可能会枚举**文件和目录**，或在主机或网络共享的特定位置搜索文件系统内的某些信息。
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。

## 利用场景
- **Windows**
  - 使用如`dir`和`tree`**程序**获取信息。
  - 使用**自定义工具**收集文件和目录信息并与Windows API进行交互。
- **Mac&Linux**
  - 使用`ls`，`find`，和`locate`命令。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如收集和渗透。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### Network Service Scanning (网络服务扫描) (All)
>[原文链接](https://attack.mitre.org/techniques/T1046/)
## 背景
- 攻击者可能会尝试获取在远程主机上运行的**服务**列表，包括可能容易受到远程软件利用的服务。

## 利用场景
- 获取此信息的方法包括使用系统附带的工具进行**端口扫描**和**漏洞扫描**。
- 在云环境中，攻击者可能会尝试发现在**其他云主机**上运行的服务或环境中启用的**云服务**。如果云环境连接到本地环境，则攻击者可能能够识别在**非云系统**上运行的服务。

## 防御方式
缓解|描述
:--:|:--
禁用和删除|关闭不必要的端口和服务。
网络入侵防护|使用IDS/IPS检测和阻止远程服务扫描。
网络分段|确保遵循正确的网络分段以保护关键服务器和设备。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- **NIPS**可以用来识别扫描活动。
- 监视**网络进程**使用并检查网络内部流量以检测端口扫描。


***

### Network Share Discovery (网络共享发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1135/)
## 背景
- 网络通常包含**共享**的网络驱动器和文件夹，使用户可以访问网络上各种系统的文件目录。

## 利用场景
- **Windows**
  - Windows网络上的文件共享通过**SMB协议**进行。
  - 可使用**Net命令**`net view \remotesystem`命令在远程系统中查询可用的共享驱动器。也可以使用`net share`来查询本地系统上的共享驱动器。
  - 攻击者可能会寻找在远程系统上**共享**的文件夹和驱动器，作为识别信息源的手段，并确定横向移动的目标。
- **Mac**
  - 使用`df -aH`**命令**查看本地安装的共​​享。
- **云**
  - 云虚拟网络可能包含**远程网络共享或文件存储服务**，对手在获得对系统的访问权限后可以访问这些服务。
  - 例如，AWS、GCP和Azure支持创建NFS（网络文件系统）**共享**和服务器消息块SMB（网络文件系统）共享，这些共享可以映射到终端或云系统上。。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- - 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。
- 在基于云的系统中，**本机日志记录**可用于标识对某些可能包含系统信息的api和仪表盘的访问。

***

### Network Sniffing (网络嗅探) (All)
>[原文链接](https://attack.mitre.org/techniques/T1040/)

同第五部分“Credential Access”

### Password Policy Discovery (密码策略发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1087/)
## 背景
- 密码策略是一种强制执行复杂密码的方法。
- 攻击者可能试图访问有关企业网络内使用的**密码策略**的详细信息。

## 利用场景
- 这将帮助攻击者创建一个常见密码列表，并发动遵守该策略的**字典攻击**或**蛮力攻击**。
- 如，最小密码长度，密码强制包含元素数量，账户锁定策略等。
- **Windows**
  - `net accounts`
  - `net accounts /domain`
- **Linux**
  - `chage -l`
  - `cat /etc/pam.d/common-password`
- **macOS**
  - `pwpolicy getaccountpolicies`

## 防御方式
缓解|描述
:--:|:--
密码策略|确保仅注册有效的Password Filter。D​​LL必须存在于域控制器或本地计算机的Windows安装目录，默认`C:\Windows\System32\`中，并在其中具有相应的条目`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages`。

## 检测
- 监视可能指示正用于密码策略发现的工具和命令行参数的**进程**。将该活动与系统中的其他可疑活动**关联**起来，以减少来自有效用户或管理员活动的潜在误报。
- 攻击者可能会在操作的早期尝试查找密码策略，并且该活动可能与其他发现活动一起发生。

***

### Peripheral Device Discovery (外围设备发现)
>[原文链接](https://attack.mitre.org/techniques/T1120/)
## 背景
- 攻击者可能会尝试收集有关连接到计算机系统的**外围设备和组件的信息**。

## 利用场景
- 可以用于增强攻击者对**系统和网络环境**的了解，也可用于进一步的操作。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。


***

### Permission Groups Discovery (权限组发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1069/)
## 背景
- 攻击者可能会尝试查找本地系统或域级别的**组和权限**设置。

## 利用场景
- **Windows**
  - 使用Net程序列出组，`net group /domain`和`net localgroup`。
- **Mac**
  - `dscacheutil -q group`列出域，`dscl . -list /Groups`列出本地组。
- **Linux**
  - `ldapsearch`列出域，`groups`列出本地组。
- **Office 365&Azure AD**
  - 通过身份验证后的访问，可以使用多种工具查找权限组。
  - PowerShell命令Get-MsolRole可用于获取Exchange和Office 365帐户的角色和权限组。
  - Azure CLI（AZ CLI）提供了一个界面以获取对域进行身份验证访问的权限组。
  - 使用命令`az ad user get-member-groups`将列出与用户帐户关联的组。

## 防御方式

- 属于系统功能滥用，无法简单缓解。
  
## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。


***

### Process Discovery (进程发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1057/)
## 背景
- 攻击者可能会尝试获取有关系统上正在运行的**进程信息**。

## 利用场景
- 获得的信息可用于了解网络内系统上运行的**软件**。
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。
- **Windows**
  - 使用Tasklist的`tasklist`命令或其他工具。
- **Mac&Linux**
  - 使用`ps`命令或其他工具。


## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### Query Registry (注册表查询) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1012/)
## 背景
- 攻击者可能会与Windows**注册表**进行交互，以收集有关系统，配置和已安装软件的信息。
- 注册表包含有关操作系统，配置，软件和安全的大量信息。

## 利用场景
- 一些信息可能会帮助对手进一步**扩大攻击面**。
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 与Windows注册表的交互可能来自的**命令行**，也可能是通过通过API与注册表交互运行恶意软件。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。
  
***

### Remote System Discovery (远程系统发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1018/)
## 背景
- 攻击者可能会尝试通过IP地址，主机名或网络上其他可用于从当前系统进行横向移动的逻辑标识符获取**其他系统**的列表。


## 利用场景
- **远程访问工具中**可以存在功能来实现此目的，也可以使用操作系统上的**系统程序**。
- 攻击者还可以使用**本地主机文件**，以发现主机名到远程系统的IP地址的映射。
- **Windows**
  - 使用Net的`ping`或`net view`命令。
  - 查看`C:\Windows\System32\Drivers\etc\hosts`文件内容。
- **Mac**
  - 通过**bonjour协议**在同一广播域内发现其他基于Mac的系统。
  - `ping`等程序。
  - `/etc/hosts`文件内容。
- **Linux**
  - `ping`等程序。
  - `/etc/hosts`文件内容。
- **云**
  - 在云环境中，可以根据主机操作系统使用上述技术来发现远程系统。
  - 另外，云环境通常向**API**提供有关远程系统和服务的信息。


## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### Security Software Discovery (安全软件发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1063/)
## 背景
- 攻击者可能会尝试获取系统上安装的**安全软件、配置、防御工具和传感器**的列表，包括**本地防火墙规则**和**防病毒策略**等内容。

## 利用场景
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。
- **Windows**
  - Reg的netsh程序，`reg query`命令。
  - cmd `dir`命令。
  - Tasklist任务列表。
  - 其他第三方工具。
- **Mac**
  - 对LittleSnitch和KnockKnock的检查

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### Software Discovery (软件发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1518/)
## 背景
- 攻击者可能会尝试获取系统上安装的与安全无关的**软件列表**。

## 利用场景
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***
### System Information Discovery (系统信息发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1082/)
## 背景
- 攻击者可能试图获取有关操作系统和硬件的详细信息，包括**版本、补丁、更新程序，服务包和体系架构**。

## 利用场景
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。
- **Windows**
  - cmd `ver`、`dir`、`Systeminfo`命令。
- **Mac**
  - `systemsetup`命令（需要管理员权限）。
  - `system_profiler`命令，无需配置权限即可给出配置，防火墙规则，已安装的卷，硬件以及许多其他内容进行非常详细的分类信息。
- **AWS**
  - 在Amazon Web Services（AWS）中，使用Application Discovery Service来标识服务器，虚拟机，软件和运行中的软件依赖项。
- **GCP**
  - 在Google Cloud Platform（GCP）上，使用`GET /v1beta1/{{parent=organizations/}}/assets`或`POST /v1beta1/{{parent=organizations/}}/assets:runDiscovery`可用于列出组织的云资产，或在云环境上执行资产发现。
- **Azure**
  - 在Azure中，API请求`https://management.azure.com/subscriptions/{{subscriptionId}}/resourceGroups/{{resourceGroupName}}/providers/Microsoft.Compute/virtualMachines/{{vmName}}?api-version=2019-03-01`可用于检索有关虚拟机的模型或实例视图的信息。。

## 防御方式
- 属于系统功能滥用，无法简单缓解。
  
## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。
- 在基于云的系统中，**本机日志记录**可用于标识对某些可能包含系统信息的api和仪表盘的访问。

***

### System Network Configuration Discovery (网络系统配置发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1016/)
## 背景
- 对手可能会寻找有关其访问的系统的**网络配置和设置的详细信息**，或通过远程系统的信息发现。

## 利用场景
- 使用Arp、ipconfig/ifconfig、nbtstat和route收集信息。
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。


## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### System Network Connections Discovery (网络系统连接发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1049/)
## 背景
- 攻击者可通过查询网络上的信息，尝试获取当前正在访问的受损系统或远程系统的**网络连接列表**。

## 利用场景
- 确定**横向移动**目标。
- 获得对云环境一部分系统的访问权限，可以绘制虚拟私有云或虚拟网络，以确定连接了哪些系统和服务。
- **Windows**
  - netstat程序。
  - Net的`net use`、`net session`命令。
- **Mac&Linux**
  - `netstat`和`lsof`可用来列出当前连接。
  - `who -a`和`w`可用来显示当前登录的用户，类似于`net session`。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### System Owner/User Discovery (系统所有者/用户发现) (All)
>[原文链接](https://attack.mitre.org/techniques/T1033/)
## 背景
- 对手可能试图识别主要**用户**、当前登录用户、通常使用系统的用户集，或者用户**是否积极使用**系统。

## 利用场景
- 获得对云环境一部分系统的访问权限，可以绘制虚拟私有云或虚拟网络，以确定连接了哪些系统和服务。
- **Windows**
  - 可以使用多种发现技术收集信息，因为用户和用户名详细信息在整个系统中极为常见，包括运行进程所有权、文件/目录所有权、会话信息和系统日志。
- **Mac**
  - 使用`users`、`w`和`who`.命令识别当前登录的用户。
- **Linux**
  - 使用`w`和`who`命令识别当前登录的用户。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### System Service Discovery (系统服务发现) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1120/)
## 背景
- 攻击者可能会试图获取有关**注册服务的信息**。

## 利用场景
- 可以使用操作系统实用程序获取有关服务的信息的命令，如tasklist的`sc`、`tasklist/svc`和Net的`net start`，也可以使用其他工具。
- 攻击者可以在自动发现过程中使用该技术**确定后续行为**，如确认是否完全攻陷目标或成功进行特定操作。

## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- 系统和网络发现技术通常发生在敌方了解环境的整个行动中。与其他后续活动行为**关联分析**，攻击者可能会基于所获取的信息进行其他活动，如横向移动。
- 监视**进程和命令行参数**，关注为收集系统和网络信息而可能采取的操作。
  - 具有内置功能的**远程访问工具**可以直接与Windows API交互以收集信息。
  - 通过Windows**系统管理工具**（如Windows Management Instrumentation和PowerShell）获取信息。

***

### System Time Discovery (系统时间发现) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1124/)
## 背景
- Windows时间服务在域中设置和存储**系统时间**，以维护网络中系统和服务之间的时间同步。
- 攻击者可以从本地或远程系统收集**系统时间和时区**。

## 利用场景
- 可以通过多种方式收集此信息，如在Windows上执行`net time\hostname`。
- 受害者的时区也可以从当前系统时间推断，也可以使用`w32tm/tz`收集。


## 防御方式
- 属于系统功能滥用，无法简单缓解。

## 检测
- **命令行界面监视**检测用于收集系统时间或时区的net.exe或其他命令行程序。
- 检测用于收集这些信息的**API**，但合法软件可能经常使用它们。

***

### Virtualization/Sandbox Evasion(虚拟机/沙盒规避)(All)
>[原文链接](https://attack.mitre.org/techniques/T1497/)

同第四部分“Privilege Escalation”

***

***

## Lateral Movement(横向移动）
>攻击者试图更多的了解目标环境。

**横向移动**包括攻击者用来进入和控制网络上的远程系统的技术。要攻陷**主要目标**，通常需要探索网络并锁定，然后才能访问它。要达到这一目的，往往需要通过**多个系统和账户**进行周旋。攻击者可能会安装自己的**远程访问工具**来完成横向移动，或使用**本机网络**和**操作系统工具**的合法凭据，这可能更加隐蔽。



### AppleScript (Apple脚本) (macOS)
>[原文链接](https://attack.mitre.org/techniques/T1155/)

同第二部分“Execution”

***


### Application Deployment Software (应用程序部署软件) (All)
>[原文链接](https://attack.mitre.org/techniques/T1017/)
## 背景
- 攻击者可以使用**企业管理员**的**应用程序部署系统**将恶意软件部署到网络中的系统。
- 此操作所需的**权限因系统配置而异**。本地凭据可能足以直接访问部署服务器，或可能需要特定的域凭据，很多系统可能需要管理帐户才能登录或执行软件部署。

## 利用场景
- 通过访问网络或企业范围的软件部署系统，攻击者可以在连接到部署系统的所有系统上**执行远程代码**。
- 可以**访问**能横向移动到的系统，来收集信息或引起特定效果，如擦除所有端点上的硬盘驱动器。


## 防御方式
缓解|描述
:--:|:--
代码签名|将应用程序部署系统配置为仅部署已签名的二进制文件，确保受信任的签名证书不与应用程序部署系统位于同一位置。
多因素认证|对与应用程序部署软件一起使用的帐户使用多因素身份验证。
网络细分|通过使用防火墙，帐户特权分离，组策略和多因素身份验证，确保关键网络系统的适当系统和访问隔离。
特权账户管理|仅向有限数量的授权管理员授予对应用程序部署系统的访问权限。验证可用于访问部署系统的帐户凭据是唯一的，且不在整个企业网络中使用。
更新软件|定期修补部署系统，以防止通过利用特权升级产生潜在的远程访问。

## 检测
- 从**辅助系统监视应用程序部署。
- **定期**执行应用程序部署，以便突出不定期的部署活动。
- 监视与已知可信软件不相关的过程**活动**。
- 监视部署系统上的**帐户登录**活动。

***

### Component Object Model and Distributed COM (组件对象模型和分布式COM) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1175/)

同第二部分“Execution”

***

### Exploitation of Remote Services (远程服务利用) (All)
>[原文链接](https://attack.mitre.org/techniques/T1210/)
## 背景
- 当攻击者利用程序、服务或操作系统软件或内核本身内的编程错误来执行攻击者控制的代码时，就会利用**软件漏洞**。
- 攻陷后利用远程服务的目标是**横向移动**，以实现对远程系统的**访问**。
- 攻击者可能需要确定远程系统是否处于易受攻击的状态，如通过网络服务扫描或其他发现方法来完成，以查找网络中存在的脆弱软件，缺少的某些补丁，和存在的安全软件。

## 利用场景
- **服务器**是横向移动利用的高价值目标，提供了高权限或对额外资源的访问**终端系统**也可能面临风险。
- 根据脆弱远程服务的权限级别，攻击者也可能从横向移动发起导致**特权提升**的攻击。


## 防御方式
缓解|描述
:--:|:--
应用程序隔离和沙箱|通过使用沙箱运行未知程序，使攻击者难以推进其运营。其他类型的虚拟化和应用程序微分段也可以减轻某些类型利用的影响。但这些系统中仍然存在其他漏洞。
禁用或删除功能或程序|将敏感系统可用服务减少到仅必要。
漏洞利用防护|使用各类安全应用程序，如Windows Defender（WDEG）和EMET，可用于缓解某些漏洞利用行为。控制流完整性检查也是一种方法。这但这些技术取决于系统架构和目标应用程序二进制文件的兼容性，且可能不适用于所有目标软件服务。
网络细分|适当细分网络和系统，减少对关键系统和服务的控制方法。
特权账户管理|服务账户权限和访问范围最小化。
威胁情报|强大的网络威胁情报能力可以确定哪些类型和级别的威胁可能使用软件攻击和特定组织的0day攻击。
更新软件|对内部企业终端和服务器使用补丁程序管理定期更新软件。
漏洞扫描|定期扫描内部网络以获取可用服务，以识别新的和潜在的易受攻击服务。

## 检测
- **攻击时行为**。软件攻击并不总是成功，有可能导致被攻击的进程变得不稳定或崩溃。
- **攻陷后行为**。在终端系统上查找可能指示被攻陷的行为，如进程异常行为，包括写入磁盘的可疑文件、试图隐藏执行的进程注入、发现，或与其他异常网络通信。

***

### Internal Spearphishing (内网鱼叉式网络钓鱼) (All)
>[原文链接](https://attack.mitre.org/techniques/T1534/)
## 背景
- 攻击者可以使用**内部鱼叉式网络钓鱼**来获取其他信息。
- 可以在攻陷同一组织中已经可以访问环境中的帐户或系统后，利用这些账户和系统进行攻击。

## 利用场景
- 内部鱼叉式网络钓鱼是一种**多阶段攻击**，使用已安装的恶意软件控制用户设备，或通过各种方式收集攻陷控制用户账户。
- 可以尝试利用**内部可信帐户**来增加目标中招的可能性。
- 攻击者可以利用**附件或链接**作为内部网络钓鱼的一部分来传递payload或重定向到外部站点。
- 通过在模拟登录界面上进行**输入捕获**来捕获凭据。

## 防御方式
缓解|描述
:--:|:--
电子邮件网关|部署相应设备过滤钓鱼邮件和恶意邮件。
员工培训|增强防钓鱼意识。

## 检测
- **NIDS和电子邮件网关**通常不扫描附件，但是可以利用**基于日志**的解决方案，将电子邮件的副本发送到安全服务进行脱机分析。
- 使用**内部集成**或**基于API的集成**合并服务解决方案，帮助检测内部钓鱼攻击。

***

### Logon Scripts (登录脚本) (Windows&macOS)
>[原文链接](https://attack.mitre.org/techniques/T1037/)
## 背景
- **Windows**
  - Windows允许在**特定用户或用户组**登录到系统时运行登录脚本。
  - 这些脚本可用于执行**管理功能**，这些功能通常可以执行其他程序或向内部日志服务器发送信息。
- **Mac**
  - Mac允许登录和注销**hooks**在特定用户登录或退出系统时作为**root**用户运行。

## 利用场景
  - 如果攻击者可以访问这些脚本，则可以在登录脚本中**插入代码**以执行其攻击。
  - 代码可以使他们在单个系统（本地脚本）上保持**持久性**，或在网络中**横向移动**（脚本存储在中央服务器上并推送到许多系统）。
  - 根据登录脚本的访问配置，可能需要本地或管理员帐户。


## 防御方式
缓解|描述
:--:|:--
限制文件和目录权限|将登录脚本的写访问权限限制为特定管理员。

## 检测
- 监视**登录脚本**，检测异常用户或异常时间的异常访问。
- 查找非正常帐户在正常管理职责范围之外添加或修改的**文件**。

***

### Pass the Hash (PtH通过哈希方法) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1075/)
## 背景
- Pass-the-hash（PtH）是一种无需访问用户的明文密码的**身份验证方法**。
- 此方法绕过需要明文密码的标准身份验证步骤，直接进入使用**密码散列**的身份验证部分。

## 利用场景
- 使用凭证访问技术**捕获**所使用帐户的有效密码散列。
- 捕获的散列与PtH一起用于**验证**该用户的身份。
- 一旦通过身份验证，PtH可用于在本地或远程系统上**执行**操作。
- 安装KB2871997的Windows 7及更高版本，需要有效的域用户凭据或RID 500的管理员哈希。

## 防御方式
缓解|描述
:--:|:--
密码策略|确保内置和本地管理员帐户具有复杂的唯一密码。
特权账户管理|限制系统之间的凭证重叠，降低攻击者在系统之间横向移动的能力。
系统更新|将补丁KB2871997应用到Windows 7及更高版本的系统，以限制本地管理员组中帐户的默认访问。
帐户控制|启用传递散列缓解措施，将UAC限制应用于网络登录时的本地帐户。关联的注册表项位于以下位置：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`通过GPO：`Computer Configuration > [Policies] > Administrative Templates > SCM: Pass the Hash Mitigations: Apply UAC restrictions to local accounts on network logons`。
账户管理|不允许域用户位于多个系统上的本地管理员组中。


## 检测
- **审核**所有登录和凭据使用事件并检查差异。
- 与其他可疑活动**关联**分析，如写入和执行二进制文件、异常远程登录。
- **NTLM LogonType 3**未与域登录关联且不是匿名登录的身份验证是可疑的。

***

### Pass the Ticket (PtT通过票据方法) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1097/)
## 背景
- Pass the ticket（PtT）是一种使用Kerberos票证向系统进行身份验证无需访问用户的明文密码的**身份验证方法**。
- Kerberos身份验证可以用作向远程系统**横向移动**的第一步。
- 在这种技术中，有效帐户的有效Kerberos票据由**凭证转储捕获**。
  
## 利用场景
- 根据访问级别，可以获得**用户服务票据**（user's service tickets）或**票据授予票据TGT**（Ticket Granting Ticket）。
- **用户服务票据**允许访问**特定资源**。
- **TGT**可用于从票证授予服务TGS（Ticket Granting Service）请求服务票证以访问用户有权访问的**任何资源**。
- **Silver Tickets**，用于利用，使用Kerberos作为身份验证机制，并用于生成访问该特定资源和承载资源的系统（如SharePoint）的票据服务。
- **Golden Tickets**，用于利用，使用密钥分发服务帐户/KRBTGT帐户/NTLM哈希（Key Distribution Service account KRBTGT account NTLM hash）的域，该帐户允许为活动目录中的任何帐户生成tgt。

## 防御方式
缓解|描述
:--:|:--
Active Directory配置|遏制先前生成的Golden Tickets影响，应两次重置内置的KRBTGT帐户密码，这将使使用KRBTGT哈希创建的任何现有金牌票证以及从其衍生的其他Kerberos票证无效。
密码策略|确保本地管理员帐户具有复杂的唯一密码。
特权账户管理|将域管理员帐户权限限制为域控制器和受限服务器。用过其他管理功能分离帐户。
用户帐号管理|不允许用户成为多个系统的本地管理员。

## 检测
- **审核**所有Kerberos身份验证和凭据使用事件，并检查是否存在差异。
- 与其他可疑活动（如编写和执行二进制文件）相关的异常远程身份验证事件**关联**分析，可能表示恶意活动。
- 检查**日志**，在两次重置KRBTGT密码后使用Golden Tickets金票时，在域控制器上会生成Event ID 4769。状态代码0x1F表示由于“对已解密字段进行完整性检查失败”，而导致操作失败，并指示先前无效的金票被滥用。

***

### Remote Desktop Protocol (RDP远程桌面协议) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1076/)
## 背景
- **远程桌面**是操作系统中的常见功能。它允许用户使用远程系统上的桌面图形界面登录到交互式会话。
- Microsoft将其对​​远程桌面协议（RDP）的实现称为远程桌面服务（RDS）。
- 还有其他实现和第三方工具如Teamviewer提供类似于RDS的图形访问远程服务。

## 利用场景
- 如果启用了服务并允许访问具有已知凭据的帐户，则攻击者可以通过RDP/RDS连接到远程系统以**扩展**访问权限和访问面。
- 攻击者可能会使用**凭据访问**技术来获取与RDP一起使用的凭据。
- 还可以结合使用RDP和可访问性功能技术来实现**持久性**。
- 执行**RDP会话劫持**。窃取合法用户的远程会话。通常会通知用户并有一定特征（如桌面图形消失）。
- 拥有系统权限并使用cmd`c:\windows\system32\tscon.exe [session number to be stolen]`攻击者可以劫持会话，且无需凭据或对用户的提示，可以在远程或本地，活动会话或断开连接的会话中完成。如CVE-2019-0708。
- 通过窃取域管理员或更高特权的帐户会话，还可导致**远程系统发现**和**特权升级**。
- 所有这些都可以通过使用本机Windows命令来完成，也已作为RedSnarf中的一项功能添加。

## 防御方式
缓解|描述
:--:|:--
审计|定期审核“远程桌面用户”组成员身份。从“远程桌面用户”组中删除不必要的帐户和组
禁用或删除功能程序|禁用不必要系统的RDP服务。
限制通过网络访问资源|使用远程桌面网关。
多因素认证|对远程登录使用多因素身份验证。
网络细分|限制RDP从Internet的访问。启用防火墙规则阻止网络中安全区域之间的RDP通信。
操作系统配置|更改GPO，定义更短的超时会话时间；任何单个会话可以处于活动状态的最大时间；指定断开连接的会话在RD会话主机服务器上保持活动状态的最长时间。
特权账户管理|从允许通过RDP登录的组列表中删除本地Administrators组。
用户帐号管理|如果需要远程访问，限制远程用户权限。

## 检测
- RDP的使用可能是合法的，具体取决于网络环境及其使用方式。
- 与其他因素**关联**分析，如远程登录后发生的访问和活动
- 监视登录到系统的用户**帐户**，正常帐户通常不会在相对较短的时间内访问多个系统。
- 为tscon.exe的使用设置**进程监视**，并监视在其参数中使用`cmd.exe/k`或`cmd.exe/c`来防止RDP会话劫持服务创建。

***

### Remote File Copy (远程文件拷贝) (All)
>[原文链接](https://attack.mitre.org/techniques/T1105/)

同第十部分"Command and Control"
## 背景
- 从一个系统将文件**复制**到另一个系统，在操作过程中存放攻击者工具或其他文件。

## 利用场景
- 文件可以通过**命令和控制**通道从外部系统复制，以将工具带进受害者网络，或通过与其他工具如FTP的备用协议复制。
- 文件也可以通过**本地工具**，如scp、rsync和sftp，在Mac和Linux上复制。
- 攻击者还可以在内部受攻击系统之间**横向复制**文件，可以通过使用固有的文件共享协议，如通过SMB共享文件进行远程执行的横向移动到连接的网络共享，或通过与Windows管理共享或远程桌面协议的身份验证连接。


## 防御方式
缓解|描述
:--:|:--
网络入侵防护|使用网络签名识别特定对手的恶意软件流量或通过已知工具和协议（如FTP）进行异常数据传输的NIPS/NIDS系统可用于减轻网络级别的活动。签名通常作为协议内的唯一指示符，并且可能基于特定对手或工具使用特定混淆技术，且可能在不同的恶意软件系列和版本中有所不同。随着时间的推移，攻击者可能会改变工具C2的特征码，用避免被常见防御工具发现的方式构建协议。

## 检测
- 监视**文件创建**和通过SMB在网络内的**文件传输**。
- 监视外部网络连接在系统上创建文件的**异常过程**。如使用通常不会使用的实用程序（如FTP）。
- 分析网络数据中不常见的**数据流模式**（如客户端发送的数据比从服务器接收的数据多得多）。
- 监视**程序异常**，如通常不具有网络通信功能的程序进行网络通信，或陌生程序的网络通信。
- 分析**数据包内容**以检测未遵循使用端口预期协议通信的行为。

***

### Remote Services (远程服务) (All)
>[原文链接](https://attack.mitre.org/techniques/T1021/)
## 背景
- 攻击者可以使用有效帐户登录专门用于接受远程连接的服务，如telnet，SSH和VNC。

## 利用场景
- 以登录的用户的身份执行操作。

## 防御方式
缓解|描述
:--:|:--
多因素认证|尽可能在远程服务登录上使用多因素身份验证。
用户帐号管理|限制可能使用远程服务的帐户。限制具有较高泄露风险的帐户的权限。如配置SSH，使用户只能运行特定程序。

## 检测
- 攻击者可能需要在尝试横向移动之前通过发现技术来了解环境及系统之间的关系。
- 将与远程服务相关的登录活动与异常行为，或其他恶意和可疑活动的使用相**关联**。

***

### Replication Through Removable Media(通过可移动介质复制)(All)
>[原文链接](https://attack.mitre.org/techniques/T1091/)

同第一部分“Initial Access”

***

### Shared Webroot (共享Webroot) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1051/)
## 背景
- 攻击者可以通过包含网站webroot或Web内容目录的**开放网络文件共享**，将恶意内容添加到内部可访问的网站，然后**诱导**使用Web浏览器的用户浏览该内容，使服务器执行恶意Payload。
- 恶意内容通常在Web服务器的上下文和进程拥有的权限下运行，这通常会导致**权限提升**到本地系统或管理权限，具体取决于Web服务器的配置方式。

## 利用场景
- 这种共享访问和远程执行机制可用于**横向移动**到运行Web服务器的系统。
- 例如，攻击者在使用开放网络共享运行PHP的Web服务器上，上传远程访问工具和PHP脚本，以便特定页面被访问时在运行Web服务器的系统上执行**RAT**。

## 防御方式
缓解|描述
:--:|:--
限制访问资源|禁止远程访问提供Web内容的webroot或其他目录。
网络细分|保护系统和Web服务器，与未经身份验证的网络共享访问隔离。
特权账户管理|保护系统和Web服务器以限制特权帐户的使用和未经身份验证的网络共享访问。
限制文件和目录权限|禁止在webroot内的目录上执行程序。确保对可通过Web服务器访问的目录具有适当的权限。
用户帐号管理|确保Web服务器进程的权限最小化；创建特定帐户以限制不必要的访问和权限在多个系统之间的重叠。

## 检测
- 使用**文件和进程监视**检测文件写入Web服务器的时间和方式，标识在Web服务器上运行的正常进程，并检测通常不执行的进程。

***

### SSH Hijacking (SSH劫持) (Linux&macOS)
>[原文链接](https://attack.mitre.org/techniques/T1184/)
## 背景
- Secure Shell（**SSH**）是Linux和macOS系统上远程访问的标准方法。
- 它允许用户通过**加密隧道**连接到另一个系统，通常通过密码、证书或使用非对称加密密钥对进行身份验证。

## 利用场景
- 在现有SSH会话中通过公钥认证与其他系统**建立信任关系**，将现有连接劫持到另一个系统。通过攻击SSH代理本身或通过访问代理的套接字来实现。
- 如果攻击者能够获得root访问权限，那么劫持SSH会话可以很简单。
- 破坏SSH代理还包括**拦截SSH凭据**。
- SSH劫持不同于远程服务的使用，它注入到现有的SSH会话中，而不是使用有效帐户创建新会话。

## 防御方式
缓解|描述
:--:|:--
禁用或删除功能或程序|在不需要此功能的系统上禁用代理转发，以防止滥用。
密码策略|确保具有较强SSH密钥对；除非使用了适当的保护，否则不要使用ssh-agent类的密钥存储技术。
特权账户管理|不允许以root或其他特权帐户通过SSH进行远程访问。
限制文件和目录权限|确保设置了正确的文件许可权并加固系统，防止出现根特权升级的机会。
用户帐账户控制|确保将所有私钥安全地存储在只有合法所有者才能使用强密码访问，并且经常轮换的位置。

## 检测
- 取决于网络环境和使用方式，SSH的使用可能是合法的。与其他因素例如远程登录后发生的访问模式和活动**关联**分析，以发现SSH的可疑或恶意行为。
- 监视登录到系统的**帐户**，这些用户帐户在相对较短的时间内通常不会访问多个系统。
- 监视不同用户正在使用的用户**SSH代理套接字文件**（SSH-agent socket files）。

***

### Taint Shared Content (共享内容污染) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1080/)
## 背景
- 存储在网络驱动器或其他共享位置的内容，可能会其他有效文件向其添加恶意程序、脚本或攻击代码而受到**污染**。
- 一旦用户打开共享受污染的内容，就可以**执行**恶意Payload，以便在远程系统上运行攻击者代码。
- 攻击者可以使用受污染的共享内容进行**横向移动**。

## 利用场景
- 目录共享枢轴（A directory share **pivot**）是此技术的变体，当用户访问共享网络目录时，使用其他几种技术传播恶意软件。
  - 使用目录.LNK文件的**快捷方式修改**，这些.LNK使用伪装技术，通过隐藏的文件和目录隐藏看起来像真实的目录。
  - 基于恶意.LNK的目录有一个嵌入式命令执行**欺骗**操作，该命令执行目录中隐藏的恶意软件文件，并打开真正的目标目录，使用户的预期操作仍然发生。
  - 当与经常使用的网络目录一起使用时，该技术可能导致频繁的**重复感染**和对系统的**广泛访问**，并可能导致对新的和更高权限的**帐户访问**。
- 攻击者还可能通过**二进制感染**危害共享网络目录，方法是将其代码附加或预处理到共享网络目录上的健康二进制文件中。
  - 恶意软件可能会修改正常二进制文件的**原始入口点**OEP，确保在合法代码之前执行。
  - 当被远程系统执行时，可以通过新感染的文件**继续传播**。
  - 这些感染可能针对以可执行文件扩展名结尾的二进制和非二进制格式，包括且不限于.EXE.DLL.SCR.BAT和.VBS。

## 防御方式
缓解|描述
:--:|:--
执行预防|通过使用白名单工具，如AppLocker或适当的软件限制策略，识别可能用于污染的内容或由被污染内容造成的潜在恶意软件，以及审核和/或阻止未知程序。
漏洞利用防护|使用如Microsoft增强型缓解体验工具包（EMET）等各类工具防止漏洞利用。
限制文件和目录权限|通过最小化具有写访问权限的用户来保护共享文件夹。

## 检测
- **行为**，将许多文件写入或覆盖到网络共享目录的进程可能是可疑的。
- 监视从**可移动媒体执行的进程**，检测由于命令和控制以及可能的网络发现技术而导致的恶意或异常活动（如网络连接）。
- 经常**扫描共享网络目录**，检测恶意文件、隐藏文件、.LNK文件和其他类型的文件类型，这些文件类型可能不仅在用于共享特定类型内容的目录中。

***

### Third-party Software(第三方软件)(All)
>[原文链接](https://attack.mitre.org/techniques/T1072/)

同第二部分“Execution”

***


### Windows Admin Shares (Windows管理员共享) (Windows)
>[原文链接](https://attack.mitre.org/techniques/T1077/)
## 背景
- Windows系统具有隐藏的**网络共享**，只有管理员才能访问它们，并提供了远程文件复制和其他管理功能。示例功能包括`C$`，`ADMIN$`，和`IPC$`。
- 通过使用远程系统`net use`的命令和有效凭据，Net程序可以连接到Windows管理共享。

## 利用场景
- 攻击者可以将此技术与管理员级别的有效帐户结合使用，通过服务器消息块SMB**远程访问**联网系统，使用**远程过程调用**RPC，传输文件与系统进行**交互并运行**，传输并通过**远程执行**二进制文件。
- 依赖于SMB/RPC上经过身份验证的会话，执行技术包括计划任务、服务执行和Windows管理检测等。
- 攻击者可以使用**NTLM散列**访问具有Pass the Hash，或特定配置和补丁的系统上的管理员共享。


## 防御方式
缓解|描述
:--:|:--
密码策略|不要在系统之间重用本地管理员帐户密码，并确保密码的复杂性和唯一性。
特权账户管理|拒绝远程使用本地管理员凭据登录系统。不允许域用户帐户位于多个系统的本地Administrators组中。

## 检测
- 使用Windows**日志**监视与记录。
  - **远程登录**事件和**相关的SMB活动**，可能表示进行了文件传输或执行远程进程。
  - 监视**连接到管理共享**的远程用户的操作。
- 监视在**命令行界面**上使用工具和命令连接到远程共享（如Net）的情况。
- 监视其他可用于查找远程可访问系统的**发现技术**。

***

### Windows Remote Management(Windows远程控制)(Windows)
>[原文链接](https://attack.mitre.org/techniques/T1028/)

同第二部分“Execution”

***

