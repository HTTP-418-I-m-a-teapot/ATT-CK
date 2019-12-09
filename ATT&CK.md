# [**MITRE ATT&CK Enterprise FrameWork**](https://attack.mitre.org/)

> by HTTP 418 I'm a teapot. @NSFOCUS

***

<!-- TOC -->

- [**MITRE ATT&CK Enterprise FrameWork**](#mitre-attck-enterprise-framework)
  - [Perface](#perface)
  - [Initial Access (初始访问)](#initial-access-%e5%88%9d%e5%a7%8b%e8%ae%bf%e9%97%ae)
    - [Drive-by Compromise (路过式威胁)](#drive-by-compromise-%e8%b7%af%e8%bf%87%e5%bc%8f%e5%a8%81%e8%83%81)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5)
    - [Exploit Public-Facing Application (利用大众化应用程序)](#exploit-public-facing-application-%e5%88%a9%e7%94%a8%e5%a4%a7%e4%bc%97%e5%8c%96%e5%ba%94%e7%94%a8%e7%a8%8b%e5%ba%8f)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-1)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-1)
    - [External Remote Services (外部远程服务)](#external-remote-services-%e5%a4%96%e9%83%a8%e8%bf%9c%e7%a8%8b%e6%9c%8d%e5%8a%a1)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-2)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-2)
    - [Hardware Additions (物理渗透硬件)](#hardware-additions-%e7%89%a9%e7%90%86%e6%b8%97%e9%80%8f%e7%a1%ac%e4%bb%b6)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-3)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-3)
    - [Replication Through Removable Media (通过可移动媒介复制)](#replication-through-removable-media-%e9%80%9a%e8%bf%87%e5%8f%af%e7%a7%bb%e5%8a%a8%e5%aa%92%e4%bb%8b%e5%a4%8d%e5%88%b6)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-4)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-4)
    - [Spearphishing Attachment (鱼叉式钓鱼附件)](#spearphishing-attachment-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%92%93%e9%b1%bc%e9%99%84%e4%bb%b6)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-5)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-5)
    - [Spearphishing Link (鱼叉式钓鱼链接)](#spearphishing-link-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%92%93%e9%b1%bc%e9%93%be%e6%8e%a5)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-6)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-6)
    - [Spearphishing via Service (服务式鱼叉钓鱼)](#spearphishing-via-service-%e6%9c%8d%e5%8a%a1%e5%bc%8f%e9%b1%bc%e5%8f%89%e9%92%93%e9%b1%bc)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-7)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-7)
    - [Supply Chain Compromise (供应链攻击)](#supply-chain-compromise-%e4%be%9b%e5%ba%94%e9%93%be%e6%94%bb%e5%87%bb)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-8)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-8)
    - [Trusted Relationship (受信关系)](#trusted-relationship-%e5%8f%97%e4%bf%a1%e5%85%b3%e7%b3%bb)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-9)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-9)
    - [Valid Accounts (合法账号)](#valid-accounts-%e5%90%88%e6%b3%95%e8%b4%a6%e5%8f%b7)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-10)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-10)
  - [Execution (执行)](#execution-%e6%89%a7%e8%a1%8c)
    - [AppleScript (AppleScript)](#applescript-applescript)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-11)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-11)
    - [CMSTP (CMSTP-Microsoft连接管理器配置文件安装程序)](#cmstp-cmstp-microsoft%e8%bf%9e%e6%8e%a5%e7%ae%a1%e7%90%86%e5%99%a8%e9%85%8d%e7%bd%ae%e6%96%87%e4%bb%b6%e5%ae%89%e8%a3%85%e7%a8%8b%e5%ba%8f)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-12)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-12)
    - [Command-Line Interface (命令行界面)](#command-line-interface-%e5%91%bd%e4%bb%a4%e8%a1%8c%e7%95%8c%e9%9d%a2)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-13)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-13)
    - [Compiled HTML File (.chm文件)](#compiled-html-file-chm%e6%96%87%e4%bb%b6)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-14)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-14)
    - [Component Object Model and Distributed COM (COM & DCOM)](#component-object-model-and-distributed-com-com--dcom)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-15)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-15)
    - [Control Panel Items (控制面板项)](#control-panel-items-%e6%8e%a7%e5%88%b6%e9%9d%a2%e6%9d%bf%e9%a1%b9)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-16)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-16)
    - [Dynamic Data Exchange (动态数据交换协议)](#dynamic-data-exchange-%e5%8a%a8%e6%80%81%e6%95%b0%e6%8d%ae%e4%ba%a4%e6%8d%a2%e5%8d%8f%e8%ae%ae)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-17)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-17)
    - [Execution through API (通过API执行)](#execution-through-api-%e9%80%9a%e8%bf%87api%e6%89%a7%e8%a1%8c)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-18)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-18)
    - [Execution through Module Load (通过模块加载执行)](#execution-through-module-load-%e9%80%9a%e8%bf%87%e6%a8%a1%e5%9d%97%e5%8a%a0%e8%bd%bd%e6%89%a7%e8%a1%8c)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-19)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-19)
    - [Execution for Client Execution (客户端执行的利用)](#execution-for-client-execution-%e5%ae%a2%e6%88%b7%e7%ab%af%e6%89%a7%e8%a1%8c%e7%9a%84%e5%88%a9%e7%94%a8)
      - [基于浏览器的利用](#%e5%9f%ba%e4%ba%8e%e6%b5%8f%e8%a7%88%e5%99%a8%e7%9a%84%e5%88%a9%e7%94%a8)
      - [办公应用](#%e5%8a%9e%e5%85%ac%e5%ba%94%e7%94%a8)
      - [常见第三方应用](#%e5%b8%b8%e8%a7%81%e7%ac%ac%e4%b8%89%e6%96%b9%e5%ba%94%e7%94%a8)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-20)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-20)
    - [Graphical User Interface (GUI)](#graphical-user-interface-gui)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-21)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-21)
    - [InstallUtil (InstallUtil)](#installutil-installutil)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-22)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-22)
    - [Launchctl (macOS)](#launchctl-macos)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-23)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-23)
    - [Local Job Scheduling (本地作业调度)](#local-job-scheduling-%e6%9c%ac%e5%9c%b0%e4%bd%9c%e4%b8%9a%e8%b0%83%e5%ba%a6)
      - [cron](#cron)
      - [at](#at)
      - [launchd](#launchd)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-24)
      - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-24)
    - [LSASS Driver](#lsass-driver)
    - [Mshta](#mshta)
    - [Powershell (PowerShell)](#powershell-powershell)
    - [Regsvcs/Regasm](#regsvcsregasm)
    - [Regsvr32 (Regsvr32)](#regsvr32-regsvr32)
    - [Rundll32](#rundll32)
    - [Scheduled Task (计划任务)](#scheduled-task-%e8%ae%a1%e5%88%92%e4%bb%bb%e5%8a%a1)
    - [Scripting](#scripting)
    - [Service Execution](#service-execution)
    - [Signed Binary Proxy Execution](#signed-binary-proxy-execution)
    - [Signed Script Proxy Execution](#signed-script-proxy-execution)
    - [Source](#source)
    - [Space after Filename](#space-after-filename)
    - [Third-party Software](#third-party-software)
    - [Trap](#trap)
    - [Trusted Development Utilities](#trusted-development-utilities)
    - [User Execution (用户执行)](#user-execution-%e7%94%a8%e6%88%b7%e6%89%a7%e8%a1%8c)
    - [Windows Management Instrumentation](#windows-management-instrumentation)
    - [Windows Remote Management](#windows-remote-management)
    - [XSL Script Processing](#xsl-script-processing)
  - [Persistence (持久化)](#persistence-%e6%8c%81%e4%b9%85%e5%8c%96)
    - [.bash_profile and .bashrc](#bashprofile-and-bashrc)
    - [Accessibility Features](#accessibility-features)
    - [Account Manipulation](#account-manipulation)
    - [AppCert DLLs](#appcert-dlls)
    - [AppInit DLLs](#appinit-dlls)
    - [Application Shimming](#application-shimming)
    - [Authentication Package](#authentication-package)
    - [BITS Jobs (BITS-Windows后台智能传输服务-利用)](#bits-jobs-bits-windows%e5%90%8e%e5%8f%b0%e6%99%ba%e8%83%bd%e4%bc%a0%e8%be%93%e6%9c%8d%e5%8a%a1-%e5%88%a9%e7%94%a8)
      - [背景](#%e8%83%8c%e6%99%af)
      - [武器化](#%e6%ad%a6%e5%99%a8%e5%8c%96)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-25)
      - [检测](#%e6%a3%80%e6%b5%8b)
    - [Bootkit](#bootkit)
    - [Browser Extensions](#browser-extensions)
    - [Change Default File Association](#change-default-file-association)
    - [Component Firmware (组件固件)](#component-firmware-%e7%bb%84%e4%bb%b6%e5%9b%ba%e4%bb%b6)
      - [背景](#%e8%83%8c%e6%99%af-1)
      - [武器化](#%e6%ad%a6%e5%99%a8%e5%8c%96-1)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-26)
      - [检测](#%e6%a3%80%e6%b5%8b-1)
    - [Component Object Model Hijacking (COM劫持)](#component-object-model-hijacking-com%e5%8a%ab%e6%8c%81)
      - [背景](#%e8%83%8c%e6%99%af-2)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-27)
    - [检测手段](#%e6%a3%80%e6%b5%8b%e6%89%8b%e6%ae%b5-25)
    - [Create Account](#create-account)
    - [DLL Search Order Hijacking (DLL搜索顺序劫持)](#dll-search-order-hijacking-dll%e6%90%9c%e7%b4%a2%e9%a1%ba%e5%ba%8f%e5%8a%ab%e6%8c%81)
    - [Dylib Hijacking](#dylib-hijacking)
    - [Emond](#emond)
    - [External Remote Services](#external-remote-services)
    - [File System Permissions Weakness](#file-system-permissions-weakness)
    - [Hidden Files and Directories](#hidden-files-and-directories)
    - [Hooking](#hooking)
    - [Hypervisor](#hypervisor)
    - [Image File Execution Options Injection](#image-file-execution-options-injection)
    - [Kernel Modules and Extensions](#kernel-modules-and-extensions)
    - [Launch Agent](#launch-agent)
    - [Launch Daemon](#launch-daemon)
    - [Launchctl](#launchctl)
    - [LC_LOAD_DYLIB Addition](#lcloaddylib-addition)
    - [Local Job Scheduling](#local-job-scheduling)
    - [Login Item](#login-item)
    - [Logon Scripts](#logon-scripts)
    - [LSASS Driver](#lsass-driver-1)
    - [Modify Existing Service](#modify-existing-service)
    - [Netsh Helper DLL](#netsh-helper-dll)
    - [New Service](#new-service)
    - [Office Application Startup](#office-application-startup)
    - [Path Interception](#path-interception)
    - [Plist Modification](#plist-modification)
    - [Port Knocking](#port-knocking)
    - [Port Monitors](#port-monitors)
    - [PowerShell Profile](#powershell-profile)
    - [Rc.common](#rccommon)
    - [Re-opened Applications](#re-opened-applications)
    - [Redundant Access](#redundant-access)
    - [Registry Run Keys / Startup Folder](#registry-run-keys--startup-folder)
    - [Scheduled Task](#scheduled-task)
    - [Screensaver](#screensaver)
    - [Security Support Provider](#security-support-provider)
    - [Server Software Component](#server-software-component)
    - [Service Registry Permissions Weakness](#service-registry-permissions-weakness)
    - [Setuid and Setgid](#setuid-and-setgid)
    - [Shortcut Modification](#shortcut-modification)
    - [SIP and Trust Provider Hijacking](#sip-and-trust-provider-hijacking)
    - [Startup Items](#startup-items)
    - [System Firmware](#system-firmware)
    - [Systemd Service](#systemd-service)
    - [Time Providers](#time-providers)
    - [Trap](#trap-1)
    - [Valid Accounts](#valid-accounts)
    - [Web Shell](#web-shell)
    - [Windows Management Instrumentation Event Subscription](#windows-management-instrumentation-event-subscription)
    - [Winlogon Helper DLL](#winlogon-helper-dll)
  - [Privilege Escalation (提权)](#privilege-escalation-%e6%8f%90%e6%9d%83)
    - [Access Token Manipulation (操作访问令牌)](#access-token-manipulation-%e6%93%8d%e4%bd%9c%e8%ae%bf%e9%97%ae%e4%bb%a4%e7%89%8c)
    - [Accessibility Features](#accessibility-features-1)
    - [AppCert DLLs](#appcert-dlls-1)
    - [AppInit DLLs](#appinit-dlls-1)
    - [Application Shimming](#application-shimming-1)
    - [Bypass User Account Control (UAC绕过)](#bypass-user-account-control-uac%e7%bb%95%e8%bf%87)
    - [DLL Search Order Hijacking](#dll-search-order-hijacking)
    - [Dylib Hijacking](#dylib-hijacking-1)
    - [Elevated Execution with Prompt](#elevated-execution-with-prompt)
    - [Emond](#emond-1)
    - [Exploitation for Privilege Escalation](#exploitation-for-privilege-escalation)
    - [Extra Window Memory Injection (窗口内存注入)](#extra-window-memory-injection-%e7%aa%97%e5%8f%a3%e5%86%85%e5%ad%98%e6%b3%a8%e5%85%a5)
    - [File System Permissions Weakness](#file-system-permissions-weakness-1)
    - [Hooking](#hooking-1)
    - [Image File Execution Options Injection](#image-file-execution-options-injection-1)
    - [Launch Daemon](#launch-daemon-1)
    - [New Service](#new-service-1)
    - [Parent PID Spoofing](#parent-pid-spoofing)
    - [Path Interception](#path-interception-1)
    - [Plist Modification](#plist-modification-1)
    - [Port Monitors](#port-monitors-1)
    - [PowerShell Profile](#powershell-profile-1)
    - [Process Injection (进程注入)](#process-injection-%e8%bf%9b%e7%a8%8b%e6%b3%a8%e5%85%a5)
    - [Scheduled Task](#scheduled-task-1)
    - [Service Registry Permissions Weakness](#service-registry-permissions-weakness-1)
    - [Setuid and Setgid](#setuid-and-setgid-1)
    - [SID-History Injection](#sid-history-injection)
    - [Startup Items](#startup-items-1)
    - [Sudo](#sudo)
    - [Sudo Caching](#sudo-caching)
    - [Valid Accounts](#valid-accounts-1)
    - [Web Shell](#web-shell-1)
  - [Defense Evasion (防御规避)](#defense-evasion-%e9%98%b2%e5%be%a1%e8%a7%84%e9%81%bf)
    - [Access Token Manipulation](#access-token-manipulation)
    - [Application Access Token (应用程序访问令牌) (SaaS&Office 365)](#application-access-token-%e5%ba%94%e7%94%a8%e7%a8%8b%e5%ba%8f%e8%ae%bf%e9%97%ae%e4%bb%a4%e7%89%8c-saasoffice-365)
      - [背景](#%e8%83%8c%e6%99%af-3)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-1)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-28)
      - [检测](#%e6%a3%80%e6%b5%8b-2)
    - [Binary Padding (二进制填充) (all)](#binary-padding-%e4%ba%8c%e8%bf%9b%e5%88%b6%e5%a1%ab%e5%85%85-all)
      - [背景](#%e8%83%8c%e6%99%af-4)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-2)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-29)
      - [检测](#%e6%a3%80%e6%b5%8b-3)
    - [BITS Jobs](#bits-jobs)
    - [Bypass User Account Control (UAC-用户账户控制-绕过) (Windows)](#bypass-user-account-control-uac-%e7%94%a8%e6%88%b7%e8%b4%a6%e6%88%b7%e6%8e%a7%e5%88%b6-%e7%bb%95%e8%bf%87-windows)
    - [Clear Command History (清除命令历史记录) (Linux&MacOS)](#clear-command-history-%e6%b8%85%e9%99%a4%e5%91%bd%e4%bb%a4%e5%8e%86%e5%8f%b2%e8%ae%b0%e5%bd%95-linuxmacos)
      - [背景](#%e8%83%8c%e6%99%af-5)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-3)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-30)
      - [检测](#%e6%a3%80%e6%b5%8b-4)
    - [CMSTP](#cmstp)
    - [Code Signing (代码签名) (MacOS&Windows)](#code-signing-%e4%bb%a3%e7%a0%81%e7%ad%be%e5%90%8d-macoswindows)
      - [背景](#%e8%83%8c%e6%99%af-6)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-4)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-31)
      - [检测](#%e6%a3%80%e6%b5%8b-5)
    - [Compile After Delivery (交付后编译) (All)](#compile-after-delivery-%e4%ba%a4%e4%bb%98%e5%90%8e%e7%bc%96%e8%af%91-all)
      - [背景](#%e8%83%8c%e6%99%af-7)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-5)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-32)
      - [检测](#%e6%a3%80%e6%b5%8b-6)
    - [Compiled HTML File](#compiled-html-file)
    - [Component Firmware](#component-firmware)
    - [Component Object Model Hijacking](#component-object-model-hijacking)
    - [Connection Proxy (连接代理) (All)](#connection-proxy-%e8%bf%9e%e6%8e%a5%e4%bb%a3%e7%90%86-all)
      - [背景](#%e8%83%8c%e6%99%af-8)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-6)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-33)
      - [检测](#%e6%a3%80%e6%b5%8b-7)
      - [备注](#%e5%a4%87%e6%b3%a8)
    - [Control Panel Items](#control-panel-items)
    - [DCShadow (DCShadow)](#dcshadow-dcshadow)
      - [背景](#%e8%83%8c%e6%99%af-9)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-7)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-34)
      - [检测](#%e6%a3%80%e6%b5%8b-8)
    - [Deobfuscate/Decode Files or Information (反混淆/解码)](#deobfuscatedecode-files-or-information-%e5%8f%8d%e6%b7%b7%e6%b7%86%e8%a7%a3%e7%a0%81)
      - [背景](#%e8%83%8c%e6%99%af-10)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-8)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-35)
      - [检测](#%e6%a3%80%e6%b5%8b-9)
    - [Disabling Security Tools (瘫痪安全服务) (All)](#disabling-security-tools-%e7%98%ab%e7%97%aa%e5%ae%89%e5%85%a8%e6%9c%8d%e5%8a%a1-all)
      - [背景](#%e8%83%8c%e6%99%af-11)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-9)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-36)
      - [检测](#%e6%a3%80%e6%b5%8b-10)
    - [DLL Search Order Hijacking](#dll-search-order-hijacking-1)
    - [DLL Side-Loading (DLL旁路加载) (Windows)](#dll-side-loading-dll%e6%97%81%e8%b7%af%e5%8a%a0%e8%bd%bd-windows)
      - [背景](#%e8%83%8c%e6%99%af-12)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-10)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-37)
      - [检测](#%e6%a3%80%e6%b5%8b-11)
    - [Execution Guardrails (执行边界) (All)](#execution-guardrails-%e6%89%a7%e8%a1%8c%e8%be%b9%e7%95%8c-all)
      - [背景](#%e8%83%8c%e6%99%af-13)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-11)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-38)
      - [检测](#%e6%a3%80%e6%b5%8b-12)
      - [补充](#%e8%a1%a5%e5%85%85)
    - [Exploitation for Defense Evasion (漏洞利用免杀) (All)](#exploitation-for-defense-evasion-%e6%bc%8f%e6%b4%9e%e5%88%a9%e7%94%a8%e5%85%8d%e6%9d%80-all)
      - [背景](#%e8%83%8c%e6%99%af-14)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-12)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-39)
      - [检测](#%e6%a3%80%e6%b5%8b-13)
      - [补充](#%e8%a1%a5%e5%85%85-1)
    - [Extra Window Memory Injection](#extra-window-memory-injection)
    - [File and Directory Permissions Modification (文件目录权限修改) (All)](#file-and-directory-permissions-modification-%e6%96%87%e4%bb%b6%e7%9b%ae%e5%bd%95%e6%9d%83%e9%99%90%e4%bf%ae%e6%94%b9-all)
      - [背景](#%e8%83%8c%e6%99%af-15)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-13)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-40)
      - [检测](#%e6%a3%80%e6%b5%8b-14)
      - [补充](#%e8%a1%a5%e5%85%85-2)
    - [File Deletion (文件删除) (All)](#file-deletion-%e6%96%87%e4%bb%b6%e5%88%a0%e9%99%a4-all)
      - [背景](#%e8%83%8c%e6%99%af-16)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-14)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-41)
      - [检测](#%e6%a3%80%e6%b5%8b-15)
    - [File System Logical Offsets](#file-system-logical-offsets)
      - [背景](#%e8%83%8c%e6%99%af-17)
      - [利用场景](#%e5%88%a9%e7%94%a8%e5%9c%ba%e6%99%af-15)
      - [防御方式](#%e9%98%b2%e5%be%a1%e6%96%b9%e5%bc%8f-42)
      - [检测](#%e6%a3%80%e6%b5%8b-16)
    - [Gatekeeper Bypass](#gatekeeper-bypass)
    - [Group Policy Modification](#group-policy-modification)
    - [Hidden Files and Directories](#hidden-files-and-directories-1)
    - [Hidden Users](#hidden-users)
    - [Hidden Window](#hidden-window)
    - [HISTCONTROL](#histcontrol)
    - [Image File Execution Options Injection](#image-file-execution-options-injection-2)
    - [Indicator Blocking](#indicator-blocking)
    - [Indicator Removal from Tools](#indicator-removal-from-tools)
    - [Indicator Removal on Host](#indicator-removal-on-host)
    - [Indirect Command Execution](#indirect-command-execution)
    - [Install Root Certificate](#install-root-certificate)
    - [InstallUtil](#installutil)
    - [Launchctl](#launchctl-1)
    - [LC_MAIN Hijacking](#lcmain-hijacking)
    - [Masquerading](#masquerading)
    - [Modify Registry](#modify-registry)
    - [Mshta](#mshta-1)
    - [Network Share](#network-share)
    - [Connection Removal](#connection-removal)
    - [NTFS File Attributes](#ntfs-file-attributes)
    - [Obfuscated Files or Information](#obfuscated-files-or-information)
    - [Parent PID Spoofing](#parent-pid-spoofing-1)
    - [Plist Modification](#plist-modification-2)
    - [Port Knocking](#port-knocking-1)
    - [Process Doppelgänging](#process-doppelg%c3%a4nging)
    - [Process Hollowing](#process-hollowing)
    - [Process Injection](#process-injection)
    - [Redundant Access](#redundant-access-1)
    - [Regsvcs/Regasm](#regsvcsregasm-1)
    - [Regsvr32](#regsvr32)
    - [Rootkit](#rootkit)
    - [Rundll32](#rundll32-1)
    - [Scripting](#scripting-1)
    - [Signed Binary Proxy Execution](#signed-binary-proxy-execution-1)
    - [Signed Script Proxy Execution](#signed-script-proxy-execution-1)
    - [SIP and Trust Provider Hijacking](#sip-and-trust-provider-hijacking-1)
    - [Software Packing](#software-packing)
    - [Space after Filename](#space-after-filename-1)
    - [Template Injectio](#template-injectio)
    - [Timestomp](#timestomp)
    - [Trusted Developer Utilities](#trusted-developer-utilities)
    - [Valid Accounts](#valid-accounts-2)
    - [Virtualization/Sandbox Evasion](#virtualizationsandbox-evasion)
    - [Web Service](#web-service)
    - [XSL Script Processing](#xsl-script-processing-1)
  - [Credential Access (凭证访问)](#credential-access-%e5%87%ad%e8%af%81%e8%ae%bf%e9%97%ae)
    - [Account Manipulation](#account-manipulation-1)
    - [Bash History](#bash-history)
    - [Brute Force](#brute-force)
    - [Credential Dumping](#credential-dumping)
    - [Credentials from Web Browsers](#credentials-from-web-browsers)
    - [Credentials in Files](#credentials-in-files)
    - [Credentials in Registry](#credentials-in-registry)
    - [Exploitation for Credential Access](#exploitation-for-credential-access)
    - [Forced Authentication](#forced-authentication)
    - [Hooking](#hooking-2)
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
    - [Query Registry (查询注册表)](#query-registry-%e6%9f%a5%e8%af%a2%e6%b3%a8%e5%86%8c%e8%a1%a8)
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
  - [Lateral Movement (横向移动)](#lateral-movement-%e6%a8%aa%e5%90%91%e7%a7%bb%e5%8a%a8)
    - [AppleScript](#applescript)
    - [Application Access Token](#application-access-token)
    - [Application Deployment Software](#application-deployment-software)
    - [Component Object Model and Distributed COM](#component-object-model-and-distributed-com)
    - [Exploitation of Remote Services](#exploitation-of-remote-services)
    - [Internal Spearphishing](#internal-spearphishing)
    - [Logon Scripts](#logon-scripts-1)
    - [Pass the Hash](#pass-the-hash)
    - [Pass the Ticket](#pass-the-ticket)
    - [Remote Desktop Protocol](#remote-desktop-protocol)
    - [Remote File Copy](#remote-file-copy)
    - [Remote Services (远程服务)](#remote-services-%e8%bf%9c%e7%a8%8b%e6%9c%8d%e5%8a%a1)
    - [Replication Through Removable Media](#replication-through-removable-media)
    - [Shared Webroot](#shared-webroot)
    - [SSH Hijacking](#ssh-hijacking)
    - [Taint Shared Content](#taint-shared-content)
    - [Third-party Software](#third-party-software-1)
    - [Web Session Cookie](#web-session-cookie)
    - [Windows Admin Shares](#windows-admin-shares)
    - [Windows Remote Management](#windows-remote-management-1)
  - [Collection](#collection)
    - [Audio Capture](#audio-capture)
    - [Automated Collection](#automated-collection)
    - [Clipboard Data](#clipboard-data)
    - [Data from Information Repositories](#data-from-information-repositories)
    - [Data from Local System](#data-from-local-system)
    - [Data from Network Shared Drive](#data-from-network-shared-drive)
    - [Data from Removable Media](#data-from-removable-media)
    - [Data Staged](#data-staged)
    - [Email Collection](#email-collection)
    - [Input Capture](#input-capture-1)
    - [Man in the Browser](#man-in-the-browser)
    - [Screen Capture](#screen-capture)
    - [Video Capture](#video-capture)
  - [Command and Control](#command-and-control)
    - [Commonly Used Port](#commonly-used-port)
    - [Communication Through Removable Media](#communication-through-removable-media)
    - [Connection Proxy](#connection-proxy)
    - [Custom Command and Control Protocol](#custom-command-and-control-protocol)
    - [Custom Cryptographic Protocol](#custom-cryptographic-protocol)
    - [Data Encoding](#data-encoding)
    - [Data Obfuscation](#data-obfuscation)
    - [Domain Fronting](#domain-fronting)
    - [Domain Generation Algorithms](#domain-generation-algorithms)
    - [Fallback Channels](#fallback-channels)
    - [Multi-hop Proxy](#multi-hop-proxy)
    - [Multi-Stage Channels](#multi-stage-channels)
    - [Multiband Communication](#multiband-communication)
    - [Multilayer Encryption](#multilayer-encryption)
    - [Port Knocking](#port-knocking-2)
    - [Remote Access Tools](#remote-access-tools)
    - [Remote File Copy](#remote-file-copy-1)
    - [Standard Application Layer Protocol](#standard-application-layer-protocol)
    - [Standard Cryptographic Protocol](#standard-cryptographic-protocol)
    - [Standard Non-Application Layer Protocol](#standard-non-application-layer-protocol)
    - [Uncommonly Used Port](#uncommonly-used-port)
    - [Web Service](#web-service-1)
  - [Exfiltration](#exfiltration)
    - [Automated Exfiltration](#automated-exfiltration)
    - [Data Compressed](#data-compressed)
    - [Data Encrypted](#data-encrypted)
    - [Data Transfer Size Limits](#data-transfer-size-limits)
    - [Exfiltration Over Alternative Protocol](#exfiltration-over-alternative-protocol)
    - [Exfiltration Over Command and Control Channel](#exfiltration-over-command-and-control-channel)
    - [Exfiltration Over Other Network Medium](#exfiltration-over-other-network-medium)
    - [Exfiltration Over Physical Medium](#exfiltration-over-physical-medium)
    - [Scheduled Transfer](#scheduled-transfer)
  - [Impact](#impact)
    - [Account Access Removal](#account-access-removal)
    - [Data Destruction](#data-destruction)
    - [Data Encrypted for Impact](#data-encrypted-for-impact)
    - [Defacement](#defacement)
    - [Disk Content Wipe](#disk-content-wipe)
    - [Disk Structure Wipe](#disk-structure-wipe)
    - [Endpoint Denial of Service](#endpoint-denial-of-service)
    - [Firmware Corruption](#firmware-corruption)
    - [Inhibit System Recovery](#inhibit-system-recovery)
    - [Network Denial of Service](#network-denial-of-service)
    - [Resource Hijacking](#resource-hijacking)
    - [Runtime Data Manipulation](#runtime-data-manipulation)
    - [Service Stop](#service-stop)
    - [Stored Data Manipulation](#stored-data-manipulation)
    - [System Shutdown/RebootTransmitted Data Manipulation](#system-shutdownreboottransmitted-data-manipulation)

<!-- /TOC -->

***

## Perface

基于**MITRE ATT&CK模型**整理的文档式中译版。

建议针对**关键词语**采用双语对照，可以参照[**Initial Access**](#initial-access-%e5%88%9d%e5%a7%8b%e8%ae%bf%e9%97%ae)。

目前本文档处于未完成阶段 (19.12.06)

***

## Initial Access (初始访问)

>[攻击者正试图进入您的网络](https://attack.mitre.org/tactics/TA0001/)

**初始访问** 包括使用 **各种入口向量** 在网络中获得其 **初始入侵点** 的技术。用于获取 **入侵点** 技术包括 **针对性的鱼叉攻击** 和 **公共Web服务器** 。通过 **初始访问** 获得的 **入侵点** 可能支持进一步侵入，例如 **有效的帐户群** 和 **远程服务的外部使用权** ，也可能由于密码的修改而失效。

***

### Drive-by Compromise (路过式威胁)

>[原文链接](https://attack.mitre.org/techniques/T1189/)

**路过式威胁** 是指攻击者通过用户在正常浏览过程中访问网站来获得对系统的访问权限。使用此技术，通常会将用户的Web浏览器作为攻击目标，但攻击者也可能会将受侵害的网站用于非利用行为，例如获取应用程序访问令牌。

存在多种将漏洞利用代码传递给浏览器的方法，包括：

- 恶意代码的注入
- 恶意广告的投放
- 内置的Web内容 (论坛帖子、评论等等)

攻击者使用的网站通常是特定社区(例如政府，特定行业或地区)访问的网站，其目标是基于共同利益来威胁特定用户或一组用户。这种有针对性的攻击被称为战略性网络入侵或水坑攻击。

- 用户访问了托管了攻击者受控内容的网站
- 脚本会自动执行，通常会搜索存在漏洞的浏览器或插件版本
  - 可能要求用户通过启用脚本或活动的网站组件并忽略警告对话框来协助此过程
- 一旦发现有漏洞的版本，攻击代码将会传到浏览器
- 如果利用成功，那么除非有其他保护措施，否则它将使攻击者代码在用户的系统上执行
  - 在某些情况下，在提供漏洞利用代码之前，需要在初始扫描后再次访问网站
  
#### 防御方式

防御方式|描述
:--:|:--
**应用隔离与沙箱机制**|浏览器沙箱可用于减轻某些利用的影响，其他类型的虚拟化和应用程序微分段也可以减轻客户端利用的影响
**Exp防护**|查找漏洞利用过程中的行为的安全应用程序
**Web内容限制**|对于通过广告投放的恶意代码，**adblocker** 可以帮助阻止该代码首先执行。脚本阻止扩展可以帮助阻止可能在开发过程中普遍使用的JavaScript的执行
**更新软件**|确保所有浏览器和插件保持更新

#### 检测手段

- 防火墙和代理可以检查URL中潜在的已知危险域或参数
- 网络入侵检测系统，有时配合 **SSL/TLS** **MITM** 检测，可以查找已知的恶意脚本
- 合法网站的 **路过式威胁** 检测会很困难，还要寻找终端所提供的成功入侵的证据

***

### Exploit Public-Facing Application (利用大众化应用程序)

>[原文链接](https://attack.mitre.org/techniques/T1189/)

使用软件，数据或命令来利用面向 Internet 的计算机系统或程序中的脆弱点，从而导致意外或无法预期的行为。

- 系统的弱点可能是bug，故障或设计漏洞
- 这些应用程序通常是网站，但是可以包括数据库 (例如SQL)，标准服务 (例如SMB或SSH)以及具有 Internet 可访问开放套接字的任何其他应用程序
- 如果应用程序托管在基于云的基础架构上，利用这一点可能会导致底层受到损害。这可以让攻击者获得访问 **云API** 或利用弱身份和访问管理策略

#### 防御方式

防御方式|描述
:--:|:--
**应用隔离与沙箱机制**|应用程序隔离将限制被利用的目标对其他进程和系统功能的访问
**Exp防护**|**WAF** 可用于限制应用程序的暴露
**网络隔离**|使用 **DMZ** 或在独立的托管基础设施，将面向外部的服务器和服务与网络的其他部分分离
**账号权限控制**|最小化特权
**软件更新**|确保应用保持最新
**更新软件**|定期扫描外部系统的漏洞，并建立程序以在通过扫描和公开披露发现重大漏洞时快速修补系统

#### 检测手段

- 监视应用程序日志中是否有异常行为
- **DPI** 检测
- **WAF**

***

### External Remote Services (外部远程服务)

>[原文链接](https://attack.mitre.org/techniques/T1133/)

VPN，Citrix 和其他访问机制等远程服务使用户可以从外部位置连接到内部企业网络资源。经常有远程服务网关管理这些服务的连接和凭据身份验证。Windows Remote Management 等服务也可以在外部使用。

- 攻击者可以通过远程服务进行初始入侵 **和/或** 在网络中持久化
- 访问有效账户对于该服务是必须的，可以通过篡改和在入侵企业网络后获取

#### 防御方式

防御方式|描述
:--:|:--
**功能禁用**|禁用或阻止可能不必要的远程可用服务
**网络资源访问控制**|通过集中管理的集中器 (例如VPN) 和其他托管的远程访问系统，限制对远程服务的访问
**多因素认证**|对远程服务帐户使用强大的两因素或多因素身份验证
**网络隔离**|通过使用网络代理，网关和防火墙来拒绝对内部系统的直接远程访问

#### 检测手段

- 检测恶意使用有效账户对远程服务进行认证
- 收集身份验证日志并分析异常访问模式，以及正常工作时间之外的访问

***

### Hardware Additions (物理渗透硬件)

>[原文链接](https://attack.mitre.org/techniques/T1200/)

计算机附件、计算机或网络硬件可以作为获得执行的载体引入系统。 虽然 APT 组织使用的公共的很少，但是许多渗透测试人员利用物理渗透硬件来获得初始访问。 商业和开源产品利用了被动网络访问 、中间人破解 、击键注入 、通过DMA读取内核内存、向现有网络 添加新的无线访问等功能。

#### 防御方式

防御方式|描述
:--:|:--
**网络资源访问控制**|建立网络访问控制策略，如使用设备证书和 802.1x 标准。 将DHCP的使用限制在已注册的设备上，以防止未注册的设备与可信系统通信
**限制硬件安装*|通过终端安全配置和监视代理拦截未知设备和附件

#### 检测手段

资产管理系统可以帮助检测不应存在于网络中的计算机系统或网络设备。 终端传感器可以通过 **USB**、**Thunderbolt** 和其他外部设备通信端口检测添加的硬件。

***

### Replication Through Removable Media (通过可移动媒介复制)

>[原文链接](http://vulhub.org.cn/attack/techniques/T1091.md)

攻击者可以通过将恶意软件复制到可移动媒介上，利用媒体插入系统并执行的自动运行特性，转移到系统，这些系统处于未连通或气隙网络上。在 [**横向移动**](#lateral-movement-%e6%a8%aa%e5%90%91%e7%a7%bb%e5%8a%a8) 中，可以修改可移动媒介中的可执行文件，或者复制恶意软件并将其重命名，使其看起来像合法文件，从而诱使用户在独立的系统上执行它。对于 [**初始访问**](#initial-access-%e5%88%9d%e5%a7%8b%e8%ae%bf%e9%97%ae) ，可以通过手动操作媒体、修改用于初始格式化媒体的系统或修改媒体本身的固件来实现。

#### 防御方式

防御方式|描述
:--:|:--
**功能禁用**|如果不需要，可以禁用 **autorun**；如果业务操作不需要可移动媒介，则在组织策略级别上禁止或限制它
**限制硬件安装*|限制在网络中使用 USB 设备和可移动媒介

#### 检测手段

- 监视可移动媒介上的文件访问
- 检测在可移动媒介被挂载或由用户启动后执行的进程

***

### Spearphishing Attachment (鱼叉式钓鱼附件)

>[原文链接](https://attack.mitre.org/techniques/T1192/)

鱼叉式钓鱼附件是鱼叉式网络钓鱼的一种特殊变体,鱼叉附件使用了 **附加到电子邮件的恶意软件**。所有形式的鱼叉式钓鱼都是以电子方式提供的针对特定个人，公司或行业的社会工程学。在此情况下，攻击者将文件附加到钓鱼邮件中，并且依赖 [**用户执行**](#user-execution-%e7%94%a8%e6%88%b7%e6%89%a7%e8%a1%8c)。

#### 防御方式

防御方式|描述
:--:|:--
**杀毒软件**|防病毒软件可以自动隔离可疑文件
**网络入侵防护**|网络入侵防御系统以及旨在扫描和删除恶意电子邮件附件的系统可以用来阻止活动
**Web内容限制**|默认情况下，阻止不应该通过电子邮件传输的未知或未使用的附件是最佳做法，以防止某些媒介
**用户培训**|可以培训用户识别社交工程技术和电子邮件伪装

#### 检测手段

网络入侵检测系统和电子邮件网关可用于检测带有恶意附件的鱼叉式网络钓鱼。 **引爆设计** **(detonation chambers)** 也可用于识别恶意附件。解决方案可以是基于签名和行为的，但是攻击者可能以某种方式构造附件来避免这些机制。

杀毒软件在扫描存储在电子邮件服务器或用户计算机上的文件时，可能会检测到恶意文档和附件。 终端检测或网络检测可以在打开附件(例如 Microsoft Word 文档或 PDF 文件，可以连接到 internet 或生成 Powershell) 时潜在地检测恶意事件，这些事件与客户端执行和脚本的漏洞利用等技术有关。

***

### Spearphishing Link (鱼叉式钓鱼链接)

>[原文链接](https://attack.mitre.org/techniques/T1192/)

鱼叉式钓鱼链接是鱼叉式钓鱼的一种特殊变体，区别在于他是用 **链接下载电子邮件的恶意软件**，也依赖于 [**用户执行**](#user-execution-%e7%94%a8%e6%88%b7%e6%89%a7%e8%a1%8c)。连接还可以定位到意在 [**窃取应用程序访问令牌**](#access-token-manipulation-%e6%93%8d%e4%bd%9c%e8%ae%bf%e9%97%ae%e4%bb%a4%e7%89%8c) 的恶意程序

#### 防御方式

防御方式|描述
:--:|:--
**Web内容限制**|确定某些可用于造假网站的网站对于业务运营是否必要，并在无法很好地监控活动或构成重大风险的情况下考虑阻止访问
**用户培训**|可以培训用户识别社交工程技术和电子邮件伪装

#### 检测手段

检查电子邮件中的 **URL** 有助于检测指向已知恶意站点的链接。 **引爆设计** **(detonation chambers)** 可用于检测这些链接，并自动转到这些站点以确定它们是否具有潜在恶意，或在等待用户访问链接时捕获内容。 这种技术通常涉及终端上的用户交互，因此一旦用户执行，就可能检测到鱼叉式钓鱼链接。

***

### Spearphishing via Service (服务式鱼叉钓鱼)

>[原文链接](http://vulhub.org.cn/attack/techniques/T1194.md)

服务式鱼叉钓鱼是鱼叉式钓鱼的一种特殊变体，区别在于他采用的是 **第三方服务** 。

攻击者将创建虚假的社交媒体帐户，并向员工传达潜在的工作机会。这样做可以提出合理的理由来询问环境中运行的服务，策略和软件。然后，攻击者可以通过这些服务发送恶意链接或附件。

#### 防御方式

防御方式|描述
:--:|:--
**杀毒软件**|防病毒软件可以自动隔离可疑文件
**Web内容限制**|确定第三方服务对于企业的运营是否必要，不必要可以考虑阻止访问
**用户培训**|实行安全培训

#### 检测手段

由于用于 **服务式鱼叉钓鱼** 的大多数常见第三方服务利用 TLS 加密，因此通常需要 **SSL/TLS** 检查来检测初始通信/交付。 利用 **SSL/TLS** 检查入侵检测签名或其他安全网关设备可能能够检测到恶意软件。 杀毒软件可以检测用户电脑上下载的恶意文档和文件。 终端检测或网络检测可以在打开文件（例如 Microsoft Word 文档或 PDF 文件，可以连接到 internet 或生成 Powershell.exe) 时潜在地检测恶意事件，这些事件与客户端执行和脚本的漏洞利用等技术有关。

***

### Supply Chain Compromise (供应链攻击)

>[原文链接](https://attack.mitre.org/techniques/T1195/)

供应链攻击是为了最终数据或系统折衷目的而在最终消费者收到产品或产品交付机制之前对其进行的操纵。

供应链攻击可以发生在供应链的任何阶段，包括：

- 开发工具的操作
- 开发环境的操作
- 源代码库的操作
- **软件更新**/分发机制
- 受损/感染的系统映像
- 用修改的版本替换合法软件
- 向合法分销商销售修改/仿冒产品

尽管供应链的攻击可能会影响硬件或软件的任意组件，但想要获得执行的攻击者往往关注在软件分发阶段或更新渠道中对合法软件进行的恶意添加。 可以以特定的受害者群体为目标， 或将恶意软件分发给广泛的消费者群体，但仅对特定受害者的附加策略。

#### 防御方式

防御方式|描述
:--:|:--
**更新软件**|应该实施补丁程序管理过程
**漏洞扫描**|漏洞源的持续监视以及使用自动和手动代码检查工具

#### 检测手段

通过 **哈希校验** 或其他完整性校验机制来检验分布式二进制文件。扫描下载的文件查找是否有恶意签名，并尝试在部署之前测试软件和更新，同时注意潜在的可疑活动。对硬件进行物理检查以查找潜在的篡改。

***

### Trusted Relationship (受信关系)

>[原文链接](https://attack.mitre.org/techniques/T1199/)

攻击者可能会破坏或利用能够接触到目标受害者的组织。通过可信的第三方关系利用现有的连接，这些连接可能不受保护或者受到的审查比获取网络访问权的标准机制少。组织通常授予第二或第三方外部提供商高级访问权限，以允许它们管理内部系统。这些关系的例子包括IT服务承包商、托管安全供应商、基础设施承包商(例如HVAC、电梯、物理安全)。 第三方提供商的访问权可能被限制在所维护的基础结构内，但是可能与企业的其他部分在相同的网络中。这样，另一方用于访问内部网络系统的 [**合法账户**](#valid-accounts-%e5%90%88%e6%b3%95%e8%b4%a6%e5%8f%b7) 可能会遭到破坏和使用

#### 防御方式

防御方式|描述
:--:|:--
**网络隔离**|网络分割隔离无需广泛网络访问的基础设施组件
**用户帐号控制**|妥善管理可受信关系中各方使用的帐户和权限

#### 检测手段

建立对由第二方和第三方提供商以及其他受信任实体进行的活动的监视。根据关系的类型，攻击可能在执行操作之前可以访问有关目标的大量信息，尤其是在信任的关系基于IT服务的情况下。攻击者可能能够快速地朝着目标行事，因此对与凭据访问，横向移动和收集有关的行为进行适当的监视对于检测入侵至关重要。

***

### Valid Accounts (合法账号)

>[原文链接](https://attack.mitre.org/techniques/T1078/)

攻击者可以使用凭据访问技术窃取特定用户或服务帐户的凭据，或者在侦察过程的早期通过社会工程来获取凭据以获得初始访问权限。

攻击者可能使用的帐户可以分为三类：默认帐户，本地帐户和域帐户。

被盗取的凭证可用于绕过网络内系统上的各种资源的访问控制，甚至可能用于对远程系统和外部可用服务的持久化。被盗取的凭证可能还会给攻击者提供特定系统或网络受限区域的特权。攻击者可能选择不将恶意软件或工具与这些凭据提供的合法访问结合使用，使其更难被察觉。

默认帐户也不仅限于客户端计算机上的访客和管理员，还包括为设备(例如网络设备和计算机应用程序)而预先设置的帐户，无论它们是内部，开放源代码还是COTS。预先设置了用户名和密码的设备会对在安装后不进行更改的使用者构成严重威胁，它们很容易成为攻击者的目标。同样，攻击者也可以利用公开披露的私钥或被盗的私钥通过 [**远程服务**](#remote-services-%e8%bf%9c%e7%a8%8b%e6%9c%8d%e5%8a%a1) 合法地连接到远程环境。

帐户访问权，凭据和权限在整个系统网络中的重叠是令人关注的，因为攻击者可能能够跨帐户和系统打到高访问级别(即域或企业管理员)，从而绕过企业内部访问控制。

#### 防御方式

防御方式|描述
:--:|:--
**应用程序开发人员指南**|确保应用程序不会不安全地存储敏感数据或凭据。(例如，代码中的纯文本凭据，存储库中已发布的凭据或公共云存储中的凭据)
**用户帐号控制**|妥善管理可受信关系中各方使用的帐户和权限
**流量过滤**|考虑在基于云的系统上将IP白名单与用户帐户管理一起使用
**多因素认证**|将多因素身份验证 (MFA) 集成为组织策略的一部分可以极大地降低g攻击者获得对有效凭据的控制的风险
**密码策略**|在安装后和部署到生产环境之前，应立即更改使用默认用户名和密码的应用程序和设备
**账户权限控制**|例行审核域和本地帐户及其权限级别，还应包括是否启用了默认帐户，或者是否创建了未经授权的新本地帐户
**用户帐号管理**|通过身份和访问管理 (IAM) 控件，确保用户和用户组对其角色具有适当的权限

#### 检测手段

- 在整个企业和外部可访问的服务配置健壮，一致的帐户活动审核策略
- 在共享帐户(用户，管理员或服务帐户)的系统中查找可疑帐户行为
- 对域和本地系统帐户进行​​定期审核

***

## Execution (执行)

>[攻击者试图运行恶意代码](https://attack.mitre.org/tactics/TA0002/)

**执行** 是指攻击者控制的代码在本地或者远程系统上运行，通常恶意代码通常与所有其他策略结合使用，以达成更大的目标。

***

### AppleScript (AppleScript)

>[原文链接](https://attack.mitre.org/techniques/T1155/)

**macOS** 和 **OS** **X** 的应用互相发送 **AppleEvent** 消息以实现进程间通信 (IPC)。**AppleScript** 可以轻松编写本地或远程IPC的通信消息。Osascript 执行 **AppleScript** 和任何其他开放脚本编写体系结构 (OSA) 语言脚本。可以使用 **osalang** 程序找到安装在系统上的 **OSA** 语言列表

攻击者可以使用它与打开的SSH连接进行交互，移至远程计算机，甚至向用户显示虚假对话框。这些事件无法远程启动应用程序 (尽管它们可以在本地启动它们)，但是如果它们已经在远程运行，则可以与应用程序进行交互。由于这是一种脚本语言，因此它也可以用于启动更通用的技术，例如通过 python 反弹 shell 。脚本可以通过 `osascript /path/to/script` 或从命令行运行 `osascript -e "script here"`。

#### 防御方式

防御方式|描述
:--:|:--
**代码签名**|要求所有 AppleScript 在执行之前都要由受信任的开发人员 ID 签名，这将阻止随机的 AppleScript 代码执行

#### 检测手段

通过 **osascript** 监视 **AppleScript** 的执行，该脚本可能与系统上发生的其他可疑行为有关。

***

### CMSTP (CMSTP-Microsoft连接管理器配置文件安装程序)

>[原文链接](https://attack.mitre.org/techniques/T1191/)  
>[相关链接](https://www.freebuf.com/articles/system/172515.html)

Microsoft 连接管理器配置文件安装程序 (**CMSTP.exe**) 是用于安装连接管理器服务配置文件的命令行程序。**CMSTP.exe** 接受安装信息文件 (INF) 作为参数，并安装用于远程访问连接的服务配置文件。

攻击者可能向 **CMSTP.exe** 提供了感染了恶意命令的INF文件。与 [**Regsvr32**](#regsvr32-regsvr32) / [**Squiblydoo**](http://dy.163.com/v2/article/detail/EAT3L8I70511CJ6O.html) 类似，攻击者可能滥用 **CMSTP.exe** 从远程服务器 **加载和执行** **DLL**  **和/或**  **COM脚本**。由于 **CMSTP.exe** 是合法的、Microsoft 签名的应用程序，因此该执行过程也可以**绕过** **AppLocker** 和其他白名单防御。

**CMSTP.exe** 还可能被滥用于绕过用户帐户控制，并通过自动提升的COM接口执行来自恶意 **INF** 的任意命令。

#### 防御方式

防御方式|描述
:--:|:--
**功能禁用**|在给定的环境中，**CMSTP.exe** 可能不是必需的 (除非用于 VPN 连接安装)
**预防执行**|如果给定系统或网络不需要 **CMSTP.exe**，可以考虑使用配置为阻止**CMSTP.exe** 执行的应用程序白名单

#### 检测手段

使用进程监视来检测和分析 **CMSTP.exe** 的执行和参数。 将 **CMSTP.exe** 最近调用与之前的已知良好参数和被加载的文件进行比较，以确定异常和潜在的攻击活动。

还可以使用 Sysmon 事件识别 **CMSTP.exe** 的潜在滥用。 检测策略可能取决于特定的攻击者程序，但可能的规则包括：

- 检测本地/远程负载加载执行：
    `Event 1 (Process creation) :ParentImage` 包含 **CMSTP.exe**
    `Event 3 (Network connection) :Image` 包含 **CMSTP.exe** 且源IP为外部IP
- 检测利用自动提升的COM进程绕过UAC：
    `Event 10 (ProcessAccess) :CallTrace` 包含 CMLUA.dll
    `Event 12 or 13 (RegistryEvent) :TargetObject` 包含 CMMGR32.exe
    监视事件，如进程创建 (Sysmon Event 1), 涉及自动提升的 CMSTP COM 窗口 比如 `CMSTPLUA (3E5FC7F9-9A51-4367-9063-A120244FBEC7)` ，`CMLUAUTIL (3E000D72-A845-4CD9-BD83-80C07C3B881F)`

***

### Command-Line Interface (命令行界面)

>[原文链接](https://attack.mitre.org/techniques/T1059/)

命令行界面提供了一种与计算机系统交互的方式，许多操作系统平台都有该功能。其在 Windows 系统上的一个例子就是 **cmd**，它可以用来执行许多任务，包括执行其他软件。命令行界面可以在本地交互，也可以通过远程桌面应用程序、反弹 shell 等进行远程交互。执行的命令以命令行界面进程的当前权限级别运行，除非该命令包含更改该执行的权限上下文的进程调用 (例如，[**计划任务**](#scheduled-task-%e8%ae%a1%e5%88%92%e4%bb%bb%e5%8a%a1))。

攻击者可以使用命令行界面与系统交互，并在操作过程中执行其他软件。

#### 防御方式

防御方式|描述
:--:|:--
**预防执行**|通过使用应用程序白名单工具来审核 **和/或** 阻止不必要的命令行

#### 检测手段

可以通过用命令行参数适当记录进程执行来捕获命令行界面活动。这些信息可以帮助他们通过攻击者使用本机进程或自定义工具的方式更多地了解攻击者行为。

***

### Compiled HTML File (.chm文件)

>[原文链接](https://attack.mitre.org/techniques/T1223/)

编译的HTML文件 (.chm文件) 通常作为 Microsoft HTML 帮助系统的一部分分发。**CHM** 文件是各种内容(如 HTML 文档、图像)和编程语言相关的脚本/web(如 VBA、JScript、Java 和 ActiveX) 的压缩编译。 **CHM** 内容使用由 HTML 帮助可执行程序 **(hh.exe)** 加载的 Internet Explorer 浏览器的底层组件显示。

攻击者可能会滥用该技术来隐藏恶意代码。包含嵌入式有效负载的自定义 .chm文件 可以传递给受害者，然后由 [**用户执行**](#user-execution-%e7%94%a8%e6%88%b7%e6%89%a7%e8%a1%8c) 触发。**.chm** 执行还可以绕过较旧 **和/或** 未打补丁的系统上的应用白名单，这些系统没有考虑通过 **hh.exe** 执行二进制文件。

#### 防御方式

防御方式|描述
:--:|:--
**预防执行**|如果给定的系统或网络不需要 hh.exe，还可以考虑使用应用程序白名单来阻止 hh.exe 执行，防止潜在的攻击者滥用
**Web内容限制**|考虑阻止已知在攻击活动中使用的可能不常见的文件类型的下载/传输和执行，比如 .chm 文件

#### 检测手段

- 监视和分析 **hh.exe** 的执行和参数。 将 **hh.exe** 最近的调用与先前已知良好参数的调用进行比较，以确定异常和潜在的攻击活动
- 非标准进程执行树也可能表明可疑或恶意行为，例如 **hh.exe** 是与其他攻击技术相关的可疑进程和活动的父进程。
- 监视 **CHM文件** 的存在和使用，特别是如果它们在环境中不按照典型的方式使用

***

### Component Object Model and Distributed COM (COM & DCOM)

>[原文链接](https://attack.mitre.org/techniques/T1175/)

攻击者可以使用 COM 和 DCOM 在本地代码执行，或是作为 [**横向移动**](#lateral-movement-%e6%a8%aa%e5%90%91%e7%a7%bb%e5%8a%a8) 的一部分，让代码远程执行。

COM是本机Windows应用程序编程接口 (API) 的组件，该组件支持软件对象之间的交互，或者实现一个或多个接口的可执行代码。通过COM，客户端对象可以调用服务器对象的方法，这些对象通常是动态链接库 (DLL) 或可执行文件 (EXE) 。 DCOM是透明的中间件，使用远程过程调用 (RPC) 技术将组件对象模型 (COM) 的功能扩展到本地计算机之外。

与本地和远程服务器COM对象进行交互的权限由注册表中的访问控制列表 (ACL) 指定。默认情况下，只有管理员可以通过DCOM远程激活和启动COM对象。

攻击者可能滥用 **COM** 来执行本地命令 **和/或**  payload。各种 **COM** 接口被爆出可通过各种编程语言 (例如C，C ++，Java和VBScript) 滥用以调用任意执行。还存在特定的 **COM** 对象，它们可以直接执行代码执行之外的功能，例如 创建 [**计划任务**](#scheduled-task-%e8%ae%a1%e5%88%92%e4%bb%bb%e5%8a%a1) ，**无文件下载/执行** 以及其他攻击性行为，例如 [**提权**](#privilege-escalation-%e6%8f%90%e6%9d%83) 和 [**持久化**](#persistence-%e6%8c%81%e4%b9%85%e5%8c%96)。

攻击者可以使用 **DCOM** 进行横向移动。 通过 **DCOM** ，在具有适当特权的用户上下文中操作的攻击者可以通过 Office 应用程序 以及其他包含不安全方法的 Windows 对象远程实现任意执行甚至直接执行 shellcode。 **DCOM** 还可以在现有文档 中执行宏，也可以直接通过 COM 创建的 Microsoft Office 应用程序实例调用 [**动态数据交换**](#dynamic-data-exchange-%e5%8a%a8%e6%80%81%e6%95%b0%e6%8d%ae%e4%ba%a4%e6%8d%a2%e5%8d%8f%e8%ae%ae) ，从而不需要恶意文档。

#### 防御方式

防御方式|描述
:--:|:--
**应用隔离与沙箱机制**|确保已启用所有 **COM** 警报和受保护的视图
功能禁用|考虑通过 `Dcomcnfg.exe` 禁用 **DCOM**
**网络隔离**|启用Windows防火墙，默认情况下会阻止 DCOM 实例化
**账号权限控制**|修改注册表设置 (直接或使用 `Dcomcnfg.exe`)`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppID\{{AppID_GUID}}`与单个 **COM** 应用程序的整个进程的安全性相关联。
**账号权限控制**|修改注册表设置 (直接或使用 `Dcomcnfg.exe`) `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole` ，与所有未设置自己的进程范围安全性的 **COM** 应用程序的系统范围安全性默认值关联

#### 检测手段

- 监视 **COM** 对象加载的 **DLL** 和通常与应用程序无关的其他模块。通过 [**查询注册表**](#query-registry-%e6%9f%a5%e8%af%a2%e6%b3%a8%e5%86%8c%e8%a1%a8) 或 [**PowerShell**](#powershell-powershell) 枚举 **COM** 对象也可能会继续恶意使用
- 监视与 **COM**对象关联的进程的产生
- 监视分布式计算环境/远程过程调用 **(DCE / RPC)** 的异常流量

***

### Control Panel Items (控制面板项)

>[原文链接](https://attack.mitre.org/techniques/T1196/)

Windows控制面板项允许用户查看和调整计算机设置。控制面板项是已注册的可执行文件 (.exe) 或控制面板文件 (.cpl)，实际上后者已经被重命名为动态链接库文件 (.dll)，他可以到处 CPIApplet 函数。控制面板项可以直接从命令行执行，也可以通过应用程序编程接口 (API) 调用以编程方式执行，或者只需双击文件。

为了易用性，控制面板项通常包括用户友好的图形菜单，在控制面板被注册加载后。

攻击者可以使用控制面板项作为 payload 来执行任意命令。恶意控制面板项可以通过以 [**鱼叉式钓鱼附件**](#spearphishing-attachment-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%92%93%e9%b1%bc%e9%99%84%e4%bb%b6) 的方式传递或作为多级恶意软件的一部分执行。控制面板项，特别是 CPL 文件，也可以绕过应用程序 **和/或** 文件扩展名白名单。

#### 防御方式

防御方式|描述
:--:|:--
**预防执行**|使用应用程序白名单工具，来识别和阻止潜在的恶意和未知.cpl文件
**限制文件和目录权限**|将控制面板项的存储和执行限制为受保护的目录

#### 检测手段

- 监视和分析与CPL文件相关的项目相关的活动
- 清单控制面板项，用于查找系统中未注册和潜在的恶意文件
  - 可执行格式注册控制面板项将具有全局唯一标识符 **(GUID)** 和在注册的注册表项`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace` 和 `HKEY_CLASSES_ROOT\CLSID{{GUID}}`这些条目可能包含有关控制面板项的信息，如其显示名称、本地文件的路径以及在控制面板中打开时执行的命令。
  - 存储在System32目录中的CPL格式注册的控制面板项目将自动显示在控制面板中。其他控制面板项目将在`Cpls`和`Extended Properties`注册表项中具有注册条目`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Control Panel`。这些条目可能包括诸如GUID，本地文件的路径以及用于以编程方式( `WinExec("c:\windows\system32\control.exe {{Canonical_Name}}", SW_NORMAL);`)或从命令行(`control.exe /name {{Canonical_Name}}`)启动文件的规范名称之类的信息
  - 某些控制面板项目可通过注册的Shell扩展名进行扩展，`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Controls Folder{{name}}\Shellex\PropertySheetHandlers`,其中{{name}}是系统项目的预定义名称。
- 分析新的控制面板项以及磁盘以查找恶意内容。 可执行文件和 CPL 格式都是兼容的可移植可执行文件 **(PE)** 映像，直到反逆向之前，都可以使用传统的工具和方法进行检查

***

### Dynamic Data Exchange (动态数据交换协议)

>[原文链接](https://attack.mitre.org/techniques/T1173/)

**DDE** 是一种用于应用程序之间的单次 **和/或** 连续进程间通信 (IPC) 客户端-服务器协议。一旦建立连接，应用程序就可以自主的交换由字符串、[温数据链接](https://blog.csdn.net/Scrat_Kong/article/details/86618907) (数据项更改时的通知)、[热数据链接](https://blog.csdn.net/Scrat_Kong/article/details/86618907) (数据项更改的副本) 以及命令执行请求组成的事务。

对象链接和嵌入 **(OLE)** 或在文档之间链接数据的功能最初是通过 **DDE** 实现的。尽管已被 **COM** 取代，但可以通过注册表项在Windows 10和大多数Microsoft Office 2016中启用DDE。

攻击者可以使用 DDE 执行任意命令。Microsoft Office 文档可以通过 **DDE** 命令 直接或通过嵌入式文件 被污染，并用于通过钓鱼活动或托管 Web 内容交付执行，避免使用 Visual Basic for Applications (VBA) 宏。在没有命令行执行权限的受感染计算机上，攻击者也可以利用 **DDE**。

#### 防御方式

防御方式|描述
:--:|:--
**应用隔离与沙箱机制**|确保已启用**受保护的视图**
**终端行为防护**|在 Windows 10 上，启用 **攻击面减少** **(ASR)** 规则，以防止 **DDE攻击** 和从 Office 程序生成子进程
**功能禁用**|可以将 Microsoft Office 功能控制安全性对应的注册表项设置为禁用 **DDE/OLE** 自动执行。 Microsoft 还创建了注册表项，以完全禁用 Word 和 Excel 中的 **DDE** 执行
**软件配置**|确保已启用 **受保护的视图** 并考虑禁用未在 **受保护的视图**中注册的 Office 程序 (如 OneNote)中的嵌入文件

#### 检测手段

- 可以扫描 **OLE** 和 Office Open XML 文件中的 **DDEAUTO**、**DDE** 和其他表明 DDE 执行的字符串
- 监视 Microsoft Office 应用程序加载 DLL 和通常与应用程序无关的其他模块
- 监视从 Microsoft Office 应用程序生成的异常进程 (如 cmd.exe)

***

### Execution through API (通过API执行)

>[原文链接](https://attack.mitre.org/techniques/T1106/)

攻击者工具可以直接使用 Windows 应用程序编程接口 (API) 来执行二进制文件。诸如 Windows API CreateProcess 这样的函数将允许程序和脚本使用适当的路径和参数启动其他进程。

例如：

```C++
CreateProcessA() & CreateProcessW()
CreateProcessAsUserA() & CreateProcessAsUserW()
CreateProcessInternalA() & CreateProcessInternalW()
CreateProcessWithLogonW() & CreateProcessWithTokenW()
LoadLibraryA() & LoadLibraryW()
LoadLibraryExA() & LoadLibraryExW()
LoadModule()
LoadPackagedLibrary()
WinExec()
ShellExecuteA() & ShellExecuteW()
ShellExecuteExA() & ShellExecuteExW()
```

#### 防御方式

防御方式|描述
:--:|:--
**预防执行**|使用适当的应用程序白名单工具，识别并阻止可能通过此技术执行的潜在恶意软件

#### 检测手段

监视 **API** 调用可能会生成大量数据，除非在特定情况下收集，否则可能无法直接用于防御，因为良性使用 Windows API 函数 (如 CreateProcess) 很常见，难以与恶意行为区分开来。使用 **API** 监控将其他事件与有关 **API** 函数调用的行为关联起来，**API** 监控将其他事件与有关 **API** 函数调用的行为关联起来，这为确定事件是否是恶意行为造成的提供了额外的上下文。按 **进程族** 和 **进程** **ID** 对活动进行关联即可。

***

### Execution through Module Load (通过模块加载执行)

>[原文链接](https://attack.mitre.org/techniques/T1129/)

**Windows模块加载程序** 可以通过任意本地路径和任意通用命名规则 (UNC) 网络路径加载DLL。此功能保留在 **NTDLL.dll** 中，并且是 **Windows原生API**，可以通过 **Win32** **API** 的 **CreateProcess()** 等调用。

模块加载DLL的方法：

- 通过制定在 **IMPORT** 目录中的 (绝对或相对) 路径名
- 通过 **EXPORT** 转发到另一个 **DLL**，该 **DLL** 具有 (绝对或相对) 路径名 (但不带扩展名)
- 通过 **NTFS** 联结或符号链接 `program.exe.local` 与包含 **IMPORT** 或转发的 EXPORTs 的目录中指定的 DLL 的 (绝对或相对) 路径名
- 通过 `<file name="filename.extension" loadFrom="fully-qualified or relative pathname"\>` 嵌入或外部的 **application manifest**。文件名是指 IMPORT 目录中的条目或转发的 EXPORT

#### 防御方式

防御方式|描述
:--:|:--
**预防执行**|使用适当的应用程序白名单工具，识别并阻止可能通过此技术执行的潜在恶意软件

#### 检测手段

合法软件一般只需要加载例程，绑定的 **DLL** 模块或 Windows 系统 **DLL** ，因此加载非已知的模块可能是可疑的。 将 **DLL** 模块加载限制在 `%SystemRoot%` 和 `%ProgramFiles%` 目录，可以防止来自不安全路径的模块加载。 **API** 监视到的模块加载有关的行为的其他事件和写入磁盘的可疑 **DLL** ，为事件提供额外的上下文有所联系，这有助于确定是否是由于恶意行为。

***

### Execution for Client Execution (客户端执行的利用)

>[原文链接](https://attack.mitre.org/techniques/T1203/)

软件可能因为不安全的开发导致了漏洞，攻击者可以通过针对性的 **exp** 来利用漏洞，执行恶意代码。通常，对攻击者最有用的 **exp** 是那些能在他人系统执行恶意代码的，有以下几种利用。

#### 基于浏览器的利用

浏览器是 [**路过式威胁**](#drive-by-compromise-%e8%b7%af%e8%bf%87%e5%bc%8f%e5%a8%81%e8%83%81) 和 [**鱼叉式钓鱼链接**](#spearphishing-link-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%92%93%e9%b1%bc%e9%93%be%e6%8e%a5) 的常见目标。系统可能在正常的浏览时受到攻击或受到恶意用户的攻击，他们通常将恶意电子邮件中的链接定位到攻击者搭建的恶意网站，不需要任何操作就可以执行 **exp**。

#### 办公应用

常见的办公软件，例如 (Microsoft Office) 也是 **鱼叉攻击** **([鱼叉式钓鱼附件](#spearphishing-attachment-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%92%93%e9%b1%bc%e9%99%84%e4%bb%b6)，[鱼叉式钓鱼链接](#spearphishing-link-%e9%b1%bc%e5%8f%89%e5%bc%8f%e9%92%93%e9%b1%bc%e9%93%be%e6%8e%a5)，[服务式鱼叉钓鱼](#spearphishing-via-service-%e6%9c%8d%e5%8a%a1%e5%bc%8f%e9%b1%bc%e5%8f%89%e9%92%93%e9%b1%bc))** 的目标。恶意文件将作为附件或下载链接的形式直接下载。 用户需要打开文档或文件才能执行 **exp**。

#### 常见第三方应用

在网络中部署的一些其他的应用程序也可以漏洞利用，例如 **Adobe** **Reader** 和 **Flash** 之类的应用 (企业中常见的应用) 也是攻击者的目标，是否需要浏览器或者用户打开它来执行，取决于软件与漏洞的性质。

#### 防御方式

防御方式|描述
:--:|:--
**应用隔离与沙箱机制**|浏览器沙箱可用于减轻某些利用的影响，但是，**沙箱逃逸**可能存在。其他类型的虚拟化和应用程序微分段 (microsegmentation) 也可以减轻客户端漏洞利用的影响
**Exp防护**|查找漏洞利用过程中的行为的安全应用程序,可用于缓解某些漏洞利用行为。控制流完整性校验是另一种可能识别和拦截软件漏洞利用的方法

#### 检测手段

检测软件漏洞利用可能比较困难，具体取决于可用的工具。 还要在终端系统上查找可能标志成功攻击的行为，例如浏览器或 Office 进程的异常行为。这可能包括写入磁盘的可疑文件、有关尝试隐藏执行的 [**进程注入**](#process-injection-%e8%bf%9b%e7%a8%8b%e6%b3%a8%e5%85%a5) 的证据、有关披露技术 **(Discovery)** 的证据，或者其他异常网络流量，可能表明额外的工具被引入系统。

***

### Graphical User Interface (GUI)

>[原文链接](https://attack.mitre.org/techniques/T1061/)

**GUI** 是与操作系统进行交互的常用方式。攻击者可以再操作过程中使用图形化界面，通常通过 **远程交互式协议** 使用系统的 **GUI**

#### 防御方式

这种方法主要由于对 **系统功能的滥用**，而不是防御方式所能解决的。

#### 检测手段

通过 **GUI** 检测执行可能会导致严重的误报。应考虑其他因素来检测可能导致攻击者通过交互式远程会话获得对系统的访问的服务滥用。

通过远程交互式会话发生的特定系统上正常行为之外的未知或异常进程启动是可疑的。收集和审核安全日志，这些日志可能显示访问和使用合法凭证来访问网络的远程系统。

***

### InstallUtil (InstallUtil)

>[原文链接](https://attack.mitre.org/techniques/T1118/)

**InstallUtil** 是一个命令行应用程序，它允许通过执行 **.NET** 二进制文件中指定的特定安全程序组件来安装和卸载资源。 **InstallUtil** 位于 **Windows** 系统上的 **.NET** 目录中：`C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe` 和 `C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe`。 `InstallUtil.exe`具有 **Microsoft** 的数字签名。 攻击者可以通过受信的 Windows 应用程序使用 InstallUtil 来代理代码的执行。 通过利用执行由 `System.ComponentModel.RunInstaller(true)` 修饰的类的二进制文件中的属性，**InstallUtil** 还可以绕过进程白名单。

#### 防御方式

防御方式|描述
:--:|:--
**功能禁用**|在给定的环境中，可能不需要 **InstallUtil**
**预防执行**|如果给定系统或网络不需要安装应用程序白名单，则该应用程序白名单可阻止 `InstallUtil.exe` 的执行

#### 检测手段

使用进程监视来监视 `InstallUtil.exe` 的执行和参数。 将 `InstallUtil.exe` 最近的调用与之前的已知良好参数调用和已执行的二进制文件进行比较，以确定异常和潜在的攻击活动。 `InstallUtil.exe` 调用前后使用的命令参数也可能有助于确定执行的二进制文件的来源和目的。

***

### Launchctl (macOS)

>[原文链接](https://attack.mitre.org/techniques/T1152/)

**Launchctl** 控制 **macOS** 的启动进程，该进程处理诸如启动代理和启动守护进程之类的事情，但是可以自己执行其他命令或程序。 **Launchctl** 支持交互地在命令行上获取子命令，甚至可以从标准输入重定向。 通过加载或重新加载启动代理或启动守护进程，攻击者可以 **持久化** 或执行他们 所做的更改。 从 launchctl 运行命令很简单，就像 `launchctl submit -l -- /Path/to/thing/to/execute "arg" "arg" "arg"`。加载，卸载和重新加载启动代理或守护进程。如果系统允许 **launchctl**，攻击者可以滥用此功能执行代码甚至绕过白名单。

#### 防御方式

防御方式|描述
:--:|:--
用户帐号管理|阻止用户安装自己的启动代理或启动守护进程，要求它们由组策略推出

#### 检测手段

[Knock Knock](https://www.isofts.org/mac-knockknock/) 可用于检测持久化程序。例如通过 **launchctl** 安装的启动代理程序或启动守护程序。 此外，每个启动代理或启动守护进程必须在磁盘上的某个位置户有可以监视的相应 **plist** 文件。 监控 **launchctl/launchd** 的进程执行，以查找异常或未知进程。

***

### Local Job Scheduling (本地作业调度)

>[原文链接](https://attack.mitre.org/techniques/T1168/)

在 **Linux** 和 **macOS** 系统上，支持多种方法可以创建预定和定期的后台作业：**cron** 、 **at** 和 **launchd**。与 Windows 系统上的 **调度任务** 不同，基于 linux 的系统上的作业调度不能远程完成，除非与已建立的远程会话 (如 secure shell (SSH))结合使用。

#### cron

通过修改 `/etc/crontab`， `/etc/cron.d/` 目录或 **Cron** 守护进程支持的其他位置可以安装系统级的 **cron** 作业。而每个用户的 **cron** 作业是通过 **crontab** 使用具有特定格式的 **crontab** 文件安装的。­它在 **macOS** 和 **Linux** 系统上都有效。

这些方法允许在没有用户交互的情况下在后台以特定的周期间隔执行命令或脚本。攻击者可以利用作业调度在系统启动时执行程序或为了持久性而在预定的基础上执行程序， 作为横向移动的一部分执行，获取 root 权限，或者在特定帐户的上下文中运行进程。

#### at

**at** 是基于 **POSIX** 的系统 (包括 **macOS** 和 **Linux** ) 用于将程序或脚本作业安排在之后的日期和/或时间执行的另一种方式，也可以用于相同的目的。

#### launchd

每个 **launchd** 作业由不同的配置属性列表 **(plist)** 文件描述，该文件类似于启动守护进程 **(Launch Daemon)** 或启动代理 **(Launch Agent)**，不过它包括名为 `StartCalendarInterval` 的附加键，该键包含一个时间值的字典。这只适用于 **macOS** 和 **OS** **X**。

#### 防御方式

防御方式|描述
:--:|:--
**用户帐号管理**|限制用户帐户的权限并修复提权向量，只有授权用户才能创建计划作业
**预防执行**|使用白名单工具识别并拦截可用于调度作业的不必要的系统实用程序或潜在恶意软件

#### 检测手段

在安装新软件期间或通过管理功能可以创建合法的计划作业。 可以从各自的实用程序监视使用 **launchd** 和 **cron** 调度的作业，以列出关于这些作业的详细信息。 监视 **launchd** 和 **cron** 任务导致的进程执行，以查找异常或未知的应用程序和行为。

***

### LSASS Driver

***

### Mshta

***

### Powershell (PowerShell)

***

### Regsvcs/Regasm

***

### Regsvr32 (Regsvr32)

***

### Rundll32

***

### Scheduled Task (计划任务)

***

### Scripting

***

### Service Execution

***

### Signed Binary Proxy Execution

***

### Signed Script Proxy Execution

***

### Source

***

### Space after Filename

***

### Third-party Software

***

### Trap

***

### Trusted Development Utilities

***

### User Execution (用户执行)

***

### Windows Management Instrumentation

***

### Windows Remote Management

***

### XSL Script Processing

***

## Persistence (持久化)

***

### .bash_profile and .bashrc

***


### Accessibility Features

***

### Account Manipulation

***

### AppCert DLLs

***

### AppInit DLLs

***

### Application Shimming

***

### Authentication Package

***

### BITS Jobs (BITS-Windows后台智能传输服务-利用)

>[原文链接](https://attack.mitre.org/techniques/T1197/)

#### 背景

- Windows后台智能传输服务(BITS)是一种通过组件对象模型(COM)公开的一种低带宽异步文件传输机制，通常由更新程序、messengers服务和其他使用空闲带宽，并在后台运行而不中断其他联网应用的程序使用；
- Microsoft提供了一个名为 **BITSAdmin** 的二进制文件和 [**PowerShell**](#powershell-powershell)，用于创建和管理文件传输。

#### 武器化

- 使用BITS在**运行恶意代码**后进行下载、执行、清理等危险操作；
- 使用BITS通过创建长期作业(>90D)或在作业完成/出错或设备重启时调用任意程序，实现**持久化**；
  > [一个案例](https://www.cnblogs.com/xiaozi/p/11833583.html)
- 使用BITS上传功能进行 **Exfiltration Over Alternative Protocol** (基于替代协议的渗透)。

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
  - 用户登录后才启用(即使将作业附加到service账户)。

***

***

### Bootkit

***

### Browser Extensions

***

### Change Default File Association

***

### Component Firmware (组件固件)

>[原文链接](https://attack.mitre.org/techniques/T1109/)

#### 背景

- 一些攻击者可能会采用复杂的手段来破坏计算机组件并**安装恶意固件**，这些固件将在操作系统和主系统固件或BIOS之外执行攻击者代码。
- 该技术可能与系统固件 **System Firmware** 类似，但是可在不具有相同的完整性检查功能与级别的其他系统组件上执行。

#### 武器化

- 可以提供对系统的**持久访问级别**，但可能会出现权限维持故障和硬盘重映像等问题。
- 可以提供逃避**基于软件的防御和完整性检查**方法。
  
#### 防御方式

- 属于系统功能滥用，无法简单缓解。
  
#### 检测

- **数据和遥测(Data and telemetry)技术**：通过设备驱动程序(进程与API)使用情况、SMART(自我监控、分析和报告技术)提供的磁盘监控提供的数据和遥测(**Data and telemetry**)，检测组件的恶意操作；但如果恶意活动发生在系统组件上，或超出操作系统安全性和完整性机制的权限，此技术可能难以检测。
- **磁盘检查与电子取证工具**：可能会显示恶意固件的迹象，例如字符串，意外的磁盘分区表条目或其他异常内存块。
- **与正常镜像对比**：将组件(包括组件固件和行为的哈希值)与已知的良好镜像进行比较。

***

### Component Object Model Hijacking (COM劫持)

>[原文链接](https://attack.mitre.org/techniques/T1122/)

#### 背景

- 组件对象模型(**COM**)是Windows中的一个系统，用于通过操作系统在软件组件之间进行交互。
- 劫持COM对象需要在Windows注册表中进行更改，以替换对合法系统组件的引用，这可能导致该组件在执行时不起作用。

#### 利用场景

- 攻击者可以使用此系统来插入通过**劫持COM引用和关系**(references and relationships )作为**持久性**手段来代替合法软件，通过正常的系统操作执行该系统组件时，将改为执行攻击者的代码。
- 攻击者很可能会劫持**经常使用的对象**，以维持一致的持久性水平，但不太可能破坏系统内的显著功能，以避免系统不稳定导致异常检测。
  
#### 防御方式

- 属于系统功能滥用，无法简单缓解。
  
### 检测手段

- **注册表**：搜索已被替换的注册表引用，即通过注册表操作将已知二进制路径替换为未知路径来检测COM劫持。
  - 即使某些第三方应用程序定义了用户COM对象，如果用户的`HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\`对象在机器之前被加载，则该项中的对象有可能是可疑的，应该进行调查。
- **软件DLL负载**：检测与COM对象注册表修改相关的任何异常DLL负载。

***

### Create Account

***

### DLL Search Order Hijacking (DLL搜索顺序劫持)

***

### Dylib Hijacking

***

### Emond

***

### External Remote Services

>同 [**外部远程服务**](#external-remote-services-%e5%a4%96%e9%83%a8%e8%bf%9c%e7%a8%8b%e6%9c%8d%e5%8a%a1)

***

### File System Permissions Weakness

***

### Hidden Files and Directories

***

### Hooking

***

### Hypervisor

***

### Image File Execution Options Injection

***

### Kernel Modules and Extensions

***

### Launch Agent

***

### Launch Daemon

***

### Launchctl

>同 [Launchctl](#launchctl-macos)

***

### LC_LOAD_DYLIB Addition

***

### Local Job Scheduling

***

### Login Item

***

### Logon Scripts

***

### LSASS Driver

***

### Modify Existing Service

***

### Netsh Helper DLL

***

### New Service

***

### Office Application Startup

***

### Path Interception

***

### Plist Modification

***

### Port Knocking

***

### Port Monitors

***

### PowerShell Profile

***

### Rc.common

***

### Re-opened Applications

***

### Redundant Access

***

### Registry Run Keys / Startup Folder

***

### Scheduled Task

>同 [计划任务](#scheduled-task-%e8%ae%a1%e5%88%92%e4%bb%bb%e5%8a%a1)

***

### Screensaver

***

### Security Support Provider

***

### Server Software Component

***

### Service Registry Permissions Weakness

***

### Setuid and Setgid

***

### Shortcut Modification

***

### SIP and Trust Provider Hijacking

***

### Startup Items

***

### System Firmware

***

### Systemd Service

***

### Time Providers

***

### Trap

***

### Valid Accounts

>同 [合法账号](#valid-accounts-%e5%90%88%e6%b3%95%e8%b4%a6%e5%8f%b7)

***

### Web Shell

***

### Windows Management Instrumentation Event Subscription

***

### Winlogon Helper DLL

***

## Privilege Escalation (提权)

***

### Access Token Manipulation (操作访问令牌)

***

### Accessibility Features

***

### AppCert DLLs

***

### AppInit DLLs

***

### Application Shimming

***

### Bypass User Account Control (UAC绕过)

***

### DLL Search Order Hijacking

> 同 [DLL 搜索顺序劫持](#dll-search-order-hijacking-dll%e6%90%9c%e7%b4%a2%e9%a1%ba%e5%ba%8f%e5%8a%ab%e6%8c%81)

***

### Dylib Hijacking

***

### Elevated Execution with Prompt

***

### Emond

***

### Exploitation for Privilege Escalation

***

### Extra Window Memory Injection (窗口内存注入)

***

### File System Permissions Weakness

***

### Hooking

***

### Image File Execution Options Injection

***

### Launch Daemon

***

### New Service

***

### Parent PID Spoofing

***

### Path Interception

***

### Plist Modification

***

### Port Monitors

***

### PowerShell Profile

***

### Process Injection (进程注入)

***

### Scheduled Task

>同 [计划任务](#scheduled-task-%e8%ae%a1%e5%88%92%e4%bb%bb%e5%8a%a1)

***

### Service Registry Permissions Weakness

***

### Setuid and Setgid

***

### SID-History Injection

***

### Startup Items

***

### Sudo

***

### Sudo Caching

***

### Valid Accounts

>同 [合法账号](#valid-accounts-%e5%90%88%e6%b3%95%e8%b4%a6%e5%8f%b7)

***

### Web Shell

***

## Defense Evasion (防御规避)

>[攻击者正试图隐藏](https://attack.mitre.org/tactics/TA0005)

**防御规避** 是指攻击者在**整条攻击链**中避免被发现的技术。包括**免杀**(uninstalling/disabling 卸载/瘫痪安全软件)和**加固**(obfuscating/encrypting 混淆/加密脚本和数据)，攻击者同样**武器化**利用受信任的进程来隐藏和伪装恶意软件。

***

### Access Token Manipulation

>同 [操作访问令牌](#access-token-manipulation-%e6%93%8d%e4%bd%9c%e8%ae%bf%e9%97%ae%e4%bb%a4%e7%89%8c)

***

### Application Access Token (应用程序访问令牌) (SaaS&Office 365)

>[原文链接](https://attack.mitre.org/techniques/T1527/)

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
- 改变文件**大小**，用以绕过不为大文件提供检测服务工具的机制(如VirusTotal)，并减少了文件被收集分析的可能性。

#### 防御方式

- 属于系统功能滥用，无法简单缓解。

#### 检测

- 基于签名的检测中，引入基于访问(on-access based)的检测与扫描技术
- 基于行为的检测中，横向移动等进行入侵的特征，可以作为指向源文件的标志

***

### BITS Jobs

>同 [BITS Jobs](#bits-jobs-bits-windows%e5%90%8e%e5%8f%b0%e6%99%ba%e8%83%bd%e4%bc%a0%e8%be%93%e6%9c%8d%e5%8a%a1-%e5%88%a9%e7%94%a8)

***

### Bypass User Account Control (UAC-用户账户控制-绕过) (Windows)

>同 [UAC 绕过](#bypass-user-account-control-uac%e7%bb%95%e8%bf%87)

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
  - 用户身份验证后(尤其是通过SSH远程登录)，`~/.bash_history`中没有该用户记录的情况
  - 有修改`HISTFILE`和`HISTFILESIZE`环境变量，删除/清空`~/.bash_history`文件操作

***

### CMSTP

>同 [CMSTP](#cmstp-cmstp-microsoft%e8%bf%9e%e6%8e%a5%e7%ae%a1%e7%90%86%e5%99%a8%e9%85%8d%e7%bd%ae%e6%96%87%e4%bb%b6%e5%ae%89%e8%a3%85%e7%a8%8b%e5%ba%8f)

***

### Code Signing (代码签名) (MacOS&Windows)

>[原文链接](https://attack.mitre.org/techniques/T1116/)

#### 背景

- 代码签名为开发人员提供的二进制文件提供了一定程度的真实性，并保证该二进制文件未被篡改；
- 攻击者会**创建、伪造和窃取**在操作过程中使用的证书，将恶意软件和工具伪装为合法二进制文件；
- 未在Linux使用。

#### 利用场景

- 可用于**绕过**要求**签名**才能在系统上执行的安全策略。

#### 防御方式

- 属于系统功能滥用，无法简单缓解。
  
#### 检测

- 收集并分析在环境中执行的软件的签名证书元数据，以查找异常的证书特征和异常值。

***

### Compile After Delivery (交付后编译) (All)

>[原文链接](https://attack.mitre.org/techniques/T1500/)

#### 背景

- 攻击者可能试图通过将文件作为**未编译的代码**交付给受害者；
- 有效载荷
  - 将需要在**执行之前进行编译**；
  - 也可以被**加密、编码和嵌入**在其他文件中；
  - 也可能以**无法识别的格式**传递给本机OS(例如，macOS / Linux上的exe)，然后再通过捆绑的编译器和执行框架重编译为适当的可执行二进制文件。
  - 有效载荷的汇编可能**生成文件和创建文件写入事件**

#### 利用场景

- 与模糊文件或信息(Obfuscated Files or Information)相似，基于文本的源代码文件可能会破坏针对可执行文件/二进制文件的保护措施的分析和审查。
  
#### 防御方式

- 属于系统功能滥用，无法简单缓解。
  
#### 检测

- **监视常见编译器**(例如csc.exe和GCC / MinGW)的执行文件路径和命令行参数，并与其他可疑行为相关联；
- **寻找非本机二进制格式以及跨平台的编译器和执行框架**(如Mono)，并确定它们在系统上是否具有合法用途。

***

### Compiled HTML File

>同 [.chm](#compiled-html-file-chm%e6%96%87%e4%bb%b6)

***

### Component Firmware

>同 [组件固件](#component-firmware-%e7%bb%84%e4%bb%b6%e5%9b%ba%e4%bb%b6)

***

### Component Object Model Hijacking

>同 [COM 劫持](#component-object-model-hijacking-com%e5%8a%ab%e6%8c%81)

***

### Connection Proxy (连接代理) (All)

>[原文链接](https://attack.mitre.org/techniques/T1090/)

#### 背景

- 攻击者可以使用连接代理在系统之间定向网络流量，或者充当与命令与服务器进行网络通信的中介，以**避免直接连接**。
- 现有许多工具可以通过**代理**或**端口重定向**达到**流量重定向**，包括HTRAN，ZXProxy和ZXPortMap。

#### 利用场景

- 攻击者使用这类代理来管理命令和控制通信，以**减少出站网络连接的数量**，在连接丢失时提供**弹性**(resiliency，即使其中一个或多个节点停止工作，整个系统也必须能继续运行)，**跨越**受害者之间现有的**可信通信路径**以避免怀疑。
- **外部连接代理**：
  - 用于**掩盖C2流量**(命令控制)的目的地，通常使用端口重定向实现。
  - 受害环境之外的脆弱系统以及已购买的基础架构(如基于云的资源或虚拟专用服务器)可能被作为pivot。
  - 基于对从受感染系统到代理的连接被调查的可能性小的原则选择代理。
  - 受害者系统将直接与Internet上的外部代理进行通信，然后该代理会将通信**转发**到C2服务器。
- **内部连接代理**:
  - 可用于**合并来自受感染系统的内部连接**。
  - 攻击者可能使用脆弱的内部系统作为代理，以**隐藏C2流量真实目的地**。
  - 代理可以将流量从网络内部的受感染系统重定向到外部C2服务器，从而**难以发现恶意流量**。
  - 另外，该网络可用于将信息从一个系统转发到另一个系统，以**避免流量广播**。
- **ssrf**

#### 防御方式

缓解|描述
:--:|:--
**网络入侵防御**|使用网络签名识别特定攻击者恶意软件流量的NIPS可用于减轻网络级别的活动。

#### 检测

- **基于特征**:
  - 通常不进行网络通信的进程使用网络；
  - 陌生进程使用网络；
  - 通常需要用户操作的进程中，用户驱动与网络活动分离。
- **数据流分析**
  - 不常见的数据流行为(客户端发送数据远大于服务器接收的数据/不应频繁通信的服务频繁通信等)；
  - 通常不进行网络通信的进程使用网络；
  - 陌生进程使用网络；
- **数据包分析**：分析数据包内容，检测端口不遵循本应使用协议的通信行为。

#### 备注

- 签名通常用于协议内的**唯一指示符**，并且可能由特定攻击者或工具使用的特定C2协议决定，在不同恶意软件系列和版本中可能不同。
- 攻击者可能会随着时间推移和协议构建**改变工具/C2的签名**，以避免被常见防御工具发现。
***

### Control Panel Items

>同 [控制面板项](#control-panel-items-%e6%8e%a7%e5%88%b6%e9%9d%a2%e6%9d%bf%e9%a1%b9)

***

### DCShadow (DCShadow)

>[原文链接](https://attack.mitre.org/techniques/T1207/)

#### 背景

- DCShadow是一种通过**注册**(或进行再次非活跃注册inactive registration)并**冒充**域控制器(DC)的行为来操作活动目录 Active Directory(AD)数据，包括对象和架构(objects and schemas)的方法。
  >[案例](https://www.secpulse.com/archives/70892.html)
- 一旦注册成功，影子DC就可以为包括凭据和密钥在内的任何域对象进行**注入和更改**，并将其复制到AD基础结构中。
- 注册恶意DC需要在AD模式的配置`Configuration`中创建新服务器和`nTDSDSA`对象，这需要管理员权限(DC的域权限或本地权限)或KRBTGT哈希。
  
#### 利用场景

- 此技术可能会**绕过系统日志记录和安全监视设备**，如SIEM产品(因为影子DC采取的操作可能不会报告给这些传感器)。
- 该技术还可以用于**更改和删除备份数据**以及其他关联的元数据，以阻止深度分析(法医分析)forensic analysis。
- 攻击者还可以利用此技术执行**SID历史记录注入**和操纵AD对象(如帐户，访问控制列表，模式schemas)以**建立持久性后门**。

#### 防御方式

- 属于系统功能滥用，无法简单缓解。

#### 检测

- **网络流量**：
  - 监视和分析与DC之间以及DC与非DC主机之间的**数据复制**(例如，对`DrsAddEntry`、`DrsReplicaAdd`，尤其是`GetNCChanges`的调用)相关的网络流量。DC复制会每15分钟自动进行一次，但也可以由攻击者或合法的紧急更改(如修改密码)触发。
  - 监视和警告AD**对象复制**(审核详细目录服务复制事件Audit Detailed Directory Service Replication `Events 4928/4929`)。
- **目录状态**：利用AD目录同步(DirSync)，监视使用AD复制cookies导致的目录状态更改。
- **Configuration**：对AD模式的配置`Configuration`进行定期基线分析，并在创建`nTDSDSA`对象时发出警报。
- **SPN使用情况**：
  - 与目录复制服务(DRS,Directory Replication Service)远程协议接口(`GUID E3514235–4B06–11D1-AB04–00C04FC2DCD2`)关联的SPN可以在不记录的情况下设置。
  - 可以检测不在 DC 组织单元(OU,organizational unit)中的计算机对Kerberos服务主体名称(SPNs, Service Principal Names)，尤其是与服务相关联的名称(以“GC/”开头)的使用情况，
  - 恶意的影子DC必须使用这两个SPN作为服务进行身份验证，才能成功完成复制过程。

***

### Deobfuscate/Decode Files or Information (反混淆/解码)

>[原文链接](https://attack.mitre.org/techniques/T1140/)

#### 背景

- 攻击者可能会使用混淆文件或信息来隐藏入侵的分析结果，根据传入信息的利用方式，可能需要使用单独的机制来解码或模糊处理该信息。这样做的方法包括恶意软件内置功能、脚本、PowerShell或使用系统上存在的程序。

#### 利用场景

- 示例之一是使用certutil解码隐藏在证书文件中的远程访问工具的可执行文件。
- 另一个示例是使用Windows `copy /b` 命令将二进制片段重新组装为恶意负载。
- 为了防止检测，有效负载可能被压缩，存档或编码。这些有效负载使用了混淆文件或信息技术，可以在初始访问期间与之后**逃避检测**。
- 有时，作为**用户执行**的一部分，可能需要用户打开灯操作以对其进行去混淆或解码处理。可能还要求用户输入密码以打开由攻击者提供的受密码保护的压缩/编码文件。
- 对手也可以使用压缩或存档脚本，例如Javascript。

#### 防御方式

- 属于系统功能滥用，无法简单缓解。

#### 检测

- 如果被混淆/加密的信息中心包含恶意软件中并使用**Windows API**，则在操作之前或之后尝试检测恶意行为，可能会取得比分析加载的库或API调用执行更好的结果。
- 如果使用**脚本**，则需要收集脚本进行分析。
- 对**执行过程和命令行**监视，以检测与脚本和系统实用程序有关的潜在恶意行为(如certutil)。
- 监视**常见存档文件应用扩展程序**(如Zip和RAR存档工具的应用和扩展程序)的执行文件路径和命令行参数，并与其他可疑行为关联，以减少来自正常用户和管理员行为的误报。

***

### Disabling Security Tools (瘫痪安全服务) (All)

>[原文链接](https://attack.mitre.org/techniques/T1809/)

#### 背景

- 攻击者可能会禁用安全服务工具，以避免对其检测。

#### 利用场景

- 关闭安全软件或事件日志记录过程；
- 删除注册表项，导致工具不会在运行时启动；
- 或采取其他方法来干扰安全扫描或事件报告。

#### 防御方式

缓解|描述
:--:|:--
**文件目录权限**|确保适当的进程、注册表和文件权限配置
**用户帐号权限**|确保用户权限配置最小化

#### 检测

- 监视**进程和命令行参数**以查看安全工具是否被杀死或停止运行。
- 监视**注册表编辑器**，是否有对与安全工具相关服务项和启动程序的修改。
- 安全工具缺少日志或事件文件报告。

***

### DLL Search Order Hijacking

>同 [DLL 搜索顺序劫持](#dll-search-order-hijacking-dll%e6%90%9c%e7%b4%a2%e9%a1%ba%e5%ba%8f%e5%8a%ab%e6%8c%81)

***

### DLL Side-Loading (DLL旁路加载) (Windows)

>[原文链接](https://attack.mitre.org/techniques/T1480/)

#### 背景

- 程序可以运行时加载指定的的DLL。错误与模糊的指定会产生问题。
- 当WinSxS(Windows并行清单)对要加载的DLL的特性不够明确时，会发生旁加载漏洞。
- 攻击者可能会利用容易受到侧向加载的合法程序来加载恶意DLL。

#### 利用场景

- 合法受信的系统软件进程中，掩盖执行的操作。

#### 防御方式

缓解|描述
:--:|:--
**审计**|使用Windows的sxstrace.exe以及手动检查，检测清单文件中是否存在软件旁路加载漏洞。
**文件目录权限**|在写保护位置安装软件。
**更新**|定期对系统与软件进行更新。

#### 检测

- 监视进程是否存在异常活动(如不使用网络的进程连接网络)。
- 跟踪DLL的元数据(如哈希)，并将在进程执行时加载的DLL与以前的执行进行比较，检测与补丁或更新无关的可疑差异。

### Execution Guardrails (执行边界) (All)

>[原文链接](https://attack.mitre.org/techniques/T1480/)

#### 背景

- 执行边界会根据目标特定环境存在的特定条件来限制执行操作。确保仅对预定目标执行payload，并减少附带损害。
- 攻击者提供有关目标系统或环境的边界值，可能包括特定网络共享名称，附加物理设备，文件，已加入的Active Directory(AD)域，本地/外部IP地址等。

#### 利用场景

- 通过利用特定于目标的值解密有效载荷，攻击者可以避免将解密密钥与payload一起打包或通过**潜在受监控的网络**连接发送，并且给payload**逆向**带来困难。
- 通常，护栏被用于控制恶意程序的运行环境与限制损害程度/范围，以**避免暴露**。
- 不同于典型的虚拟化/沙盒逃避，护栏根据可以做出**是否进一步参与**的决定，因为其指定的是针对特定目标的价值条件，而不是使其在任何环境中执行功能。

#### 防御方式

- 执行护栏很难通过预防性控制减轻，因为它能保护目标外的数据不受损害。
- 如果应保护的目标明确，则要致力于防止攻击工具在攻击链中更早的运行，并在受到损害时识别后续恶意行为。

#### 检测

- 监视在收集各种系统信息或执行其他形式信息收集(特别是在短时间内)的可疑进程。

#### 补充

- **环境密钥 Environmental keying**
  - 环境密钥是一种类型的护栏，用于从给定计算环境的特定值生成加/密密钥的加密技术。参数从给定环境的特定元素派生，并用于为加密的payload生成解密密钥。
  - 参数可以从**特定**的网络共享、物理设备、软件/软件版本、文件、已加入的AD域、系统时间、本地/外部IP地址等元素中**得出**，通过参数**生成解密密钥**。
  - 将**加密的payload**传递给目标，该目标将在执行之前使用目标的特定参数来解密有效负载。
  - 环境密钥可以使**沙箱检测、反病毒检测、众测和逆向工程**等变得困难。以减慢事件响应速度，并帮助对手隐藏TTP(tactics, techniques, and procedures 战术，技术和程序)。

***

### Exploitation for Defense Evasion (漏洞利用免杀) (All)

>[原文链接](https://attack.mitre.org/techniques/T1211/)

#### 背景

- 攻击者利用程序，服务或操作系统软件/内核本身内的程序漏洞来**执行payload**。
- 利用安全防御软件存在的漏洞，来**禁用或规避**它们。

#### 利用场景

- 攻击者利用程序，服务或操作系统软件/内核本身内的程序漏洞来**执行payload**。
- 利用安全软件存在的漏洞，来**禁用或规避**它们。
- 通过事先侦查和在系统被入侵中执行防御软件发现(Security Software Discovery)，对环境中存在的特定安全软件进行攻击。

#### 防御方式

缓解|描述
:--:|:--
**隔离与沙箱**|通过使用沙箱技术，增加攻击者利用未发现未修补的漏洞推进攻击过程的困难。虚拟化和微分段技术也可以缓解某些类型攻击影响。但这些系统中仍然存在其他利用和弱点的风险。
**漏洞利用防护**|Windows Defender漏洞利用防御WDEG、增强缓解经验工具包EMET，等针对漏洞利用过程行为的安全应用程序，可以减轻部分威胁。控制流完整性检查也可以识别和阻止软件攻击发生，但依赖于软件架构与程序二进制文件兼容性，可用性较低。
**威胁情报**|建立强大的网络威胁情报体系，以确定攻击类型与威胁级别，识别与特定组织相关的0day攻击。
**更新**|通过补丁管理定期**更新软件**与系统。

#### 检测

- 基于系统**行为**
  - 在系统被入侵不久后发生，以掩护之后可能用到的其他攻击工具；
  - 成功率不高，可能导致软件运行不稳定或崩溃；
  - 磁盘可疑行为、试图隐藏的进程注入等漏洞成功利用的特征。

#### 补充

- 微分段技术
  - [相关链接](https://www.jianshu.com/p/1921a32afd19)
  - 微分段(Micro-segmentation)是随着网络虚拟化提出的一种安全技术，通过应用该技术，能够提供在工作负载级别(workload level)上使能精细安全策略控制来保障用户业务安全。
  - 使用微分段技术的一个显著好处就是能够将安全能力集成到虚拟化工作负载中，无须硬件设备(硬件防火墙)介入，也意味着将安全策略集成到虚拟网络(virtual network)、虚拟主机(VM)、操作系统以及其他虚拟安全实例中来提供安全。

***

### Extra Window Memory Injection

>同 [窗口内存注入](#extra-window-memory-injection-%e7%aa%97%e5%8f%a3%e5%86%85%e5%ad%98%e6%b3%a8%e5%85%a5)

***

### File and Directory Permissions Modification (文件目录权限修改) (All)

>[原文链接](https://attack.mitre.org/techniques/T1222/)

#### 背景

- 文件和目录权限通常由文件目录所有者指定的**自由访问控制列表DACL**管理。
- DACL的实现可能因平台而异，但通常会明确指定用户/组可以执行的操作，如读写执行等。

#### 利用场景

- **修改指定访问权限**，以修改、替换或删除特定的文件和目录。需要根据现有权限或提权来获得文件所有权。

#### 防御方式

- 属于系统功能滥用，无法简单缓解。

#### 检测

- **监测**所有修改DACL和文件/目录所有权的尝试；
  - Windows中使用`icacls`、`takeown`、`attrib` 和PowerShell `Set-Acl`命令
  - 在MacOS/Linux中使用`chmod`、`chown`命令。
  - 以上许多是内置的系统程序且可能会生成高误报，因此应与系统正常运行基线比较，并将权限修改与其他恶意活动指示相关联。
- 对包含关键二进制/配置文件的文件夹，启用文件/目录权限**更改审核**。
- **审计Windows安全日志**(`Event ID 4670`)。

#### 补充

- **SD**：在Windows系统中，用一个安全描述符((Secrity Descriptors)的结构来保存其权限的设置信息，简称为SD，在Windows SDK中的结构名是SECURITY DESCRIPTOR", 是包括了安全设置信息的结构体。一个安全描述符包含以下信息:
  - **安全标识符**(Security dentifiers),用于记录安全对象的ID。简称为SID。
  - **DACL**(Discretionary Access ControlList,自由访问控制列表)，指出了允许和拒绝某用户或组的存取控制列表。当一个进程需要访问安全对象，系统就会检查DACL来决定进程的访问权。如果一个对象没有DACL,那么任何人都可以拥有完全的访问权限。
  - **SACL**(System Access ControlList,系统访问控制列表)，指出了在该对象上的一组存取方式(如，读、写、运行等)的存取控制权限细节的列表。还有其自身的一些控制位。SACL中的ACE能够产生访问尝试失败或成功的时候产生评估记录，在将来的release中， SACL在未授权用户尝试访问一个对象的时候发出警告
- DACL和SACL构成了整个**访问控制列表Access Control List**, 简称ACL, ACL中的每一项为**ACE(Access Control Entry)安全访问实体**。

***

### File Deletion (文件删除) (All)

>[原文链接](https://attack.mitre.org/techniques/T1107/)

#### 背景

- 攻击者在系统抛出或创建的恶意软件，工具或其他非本机原生文件，可能会留下入侵痕迹。
- 在入侵过程中删除这些文件以保持其少量占用空间，或在入侵后的清理过程中最终将其清除。
  
#### 利用场景

- 使用本机cmd函数如DEL，安全删除工具如Windows Sysinternals SDelete或其他第三方文件删除工具。
- 某些监视工具可能会收集命令行参数，但因DEL是cmd.exe中的本机函数，可能不会捕获DEL命令，。

#### 防御方式

- 属于系统功能滥用，无法简单缓解。

#### 检测

- **监视命令行**删除功能，以使其与二进制文件或攻击者可能删除并删除的其他文件相关联。
- **监视**攻击者可能会引入目标网络系统的，尚未存在的已知与**安全删除工具**。

***

### File System Logical Offsets

#### 背景
  
#### 利用场景

#### 防御方式

缓解|描述
:--:|:--

#### 检测

***

### Gatekeeper Bypass

***

### Group Policy Modification

***

### Hidden Files and Directories

***

### Hidden Users

***

### Hidden Window

***

### HISTCONTROL

***

### Image File Execution Options Injection

***

### Indicator Blocking

***

### Indicator Removal from Tools

***

### Indicator Removal on Host

***

### Indirect Command Execution

***

### Install Root Certificate

***

### InstallUtil

>同 [InstallUtil](#installutil-installutil)

***

### Launchctl

***

### LC_MAIN Hijacking

***

### Masquerading

***

### Modify Registry

***

### Mshta

***

### Network Share

***

### Connection Removal

***

### NTFS File Attributes

***

### Obfuscated Files or Information

***

### Parent PID Spoofing	

***

### Plist Modification

***

### Port Knocking

***

### Process Doppelgänging

***

### Process Hollowing

***

### Process Injection

>同 [进程注入](#process-injection-%e8%bf%9b%e7%a8%8b%e6%b3%a8%e5%85%a5)

***

### Redundant Access

***

### Regsvcs/Regasm

***

### Regsvr32

>同 [Regsvr32](#regsvr32-regsvr32)

***

### Rootkit

***

### Rundll32	

***

### Scripting

***

### Signed Binary Proxy Execution

***

### Signed Script Proxy Execution

***

### SIP and Trust Provider Hijacking

***

### Software Packing

***

### Space after Filename

***

### Template Injectio

***

### Timestomp

***

### Trusted Developer Utilities

***

### Valid Accounts

>同 [合法账号](#valid-accounts-%e5%90%88%e6%b3%95%e8%b4%a6%e5%8f%b7)

***

### Virtualization/Sandbox Evasion

***

### Web Service

***

### XSL Script Processing

***

## Credential Access (凭证访问)

***

### Account Manipulation

***

### Bash History

***

### Brute Force	

***

### Credential Dumping

***

### Credentials from Web Browsers

***

### Credentials in Files

***

### Credentials in Registry

***

### Exploitation for Credential Access

***

### Forced Authentication

***

### Hooking

***

### Input Capture

***

### Input Prompt

***

### Kerberoasting

***

### Keychain

***

### LLMNR/NBT-NS Poisoning and Relay

***

### Network Sniffing

***

### Password Filter DLL

***

### Private Keys

***

### Securityd Memory

***

### Steal Web Session Cookie

***

### Two-Factor Authentication Interception

***

## Discovery (嗅探扫描)

***

### Account Discovery

***

### Application Window Discovery

***

### Browser Bookmark Discovery

***

### Domain Trust Discovery

***

### File and Directory Discovery

***

### Network Service Scanning

***

### Network Share Discovery

***

### Network Sniffing

***

### Password Policy Discovery

***

### Peripheral Device Discovery

***

### Permission Groups Discovery

***

### Process Discovery

***

### Query Registry (查询注册表)

***

### Remote System Discovery

***

### Security Software Discovery

***

### Software Discovery

***

### System Information Discovery

***

### System Network Configuration Discovery

***

### System Network Connections Discovery

***

### System Owner/User Discovery

***

### System Service Discovery

***

### System Time Discovery

***

### Virtualization/Sandbox Evasion

***

## Lateral Movement (横向移动)

***

### AppleScript

>同 [AppleScript](#applescript-applescript)

***

### Application Access Token

>同 [应用程序访问令牌](#application-access-token-%e5%ba%94%e7%94%a8%e7%a8%8b%e5%ba%8f%e8%ae%bf%e9%97%ae%e4%bb%a4%e7%89%8c-saasoffice-365)

***

### Application Deployment Software

***

### Component Object Model and Distributed COM

***

### Exploitation of Remote Services

***

### Internal Spearphishing

***

### Logon Scripts

***

### Pass the Hash

***

### Pass the Ticket

***

### Remote Desktop Protocol

***

### Remote File Copy

***

### Remote Services (远程服务)

***

### Replication Through Removable Media

> 同 [通过可移动媒介复制](#replication-through-removable-media-%e9%80%9a%e8%bf%87%e5%8f%af%e7%a7%bb%e5%8a%a8%e5%aa%92%e4%bb%8b%e5%a4%8d%e5%88%b6)

***

### Shared Webroot

***

### SSH Hijacking

***

### Taint Shared Content

***

### Third-party Software

***

### Web Session Cookie

***

### Windows Admin Shares

***

### Windows Remote Management

***

## Collection

***

### Audio Capture

***

### Automated Collection

***

### Clipboard Data

***

### Data from Information Repositories

***

### Data from Local System

***

### Data from Network Shared Drive

***

### Data from Removable Media

***

### Data Staged

***

### Email Collection

***

### Input Capture

***

### Man in the Browser

***

### Screen Capture

***

### Video Capture

***

## Command and Control

***

### Commonly Used Port

***

### Communication Through Removable Media

***

### Connection Proxy

>同 [连接代理](#connection-proxy-%e8%bf%9e%e6%8e%a5%e4%bb%a3%e7%90%86-all)

***

### Custom Command and Control Protocol

***

### Custom Cryptographic Protocol

***

### Data Encoding

***

### Data Obfuscation

***

### Domain Fronting

***

### Domain Generation Algorithms

***

### Fallback Channels

***

### Multi-hop Proxy

***

### Multi-Stage Channels

***

### Multiband Communication

***

### Multilayer Encryption

***

### Port Knocking

***

### Remote Access Tools

***

### Remote File Copy

***

### Standard Application Layer Protocol

***

### Standard Cryptographic Protocol

***

### Standard Non-Application Layer Protocol

***

### Uncommonly Used Port

***

### Web Service

***

## Exfiltration

***

### Automated Exfiltration

***

### Data Compressed

***

### Data Encrypted

***

### Data Transfer Size Limits

***

### Exfiltration Over Alternative Protocol

***

### Exfiltration Over Command and Control Channel

***

### Exfiltration Over Other Network Medium

***

### Exfiltration Over Physical Medium

***

### Scheduled Transfer

***

## Impact

***

### Account Access Removal

***

### Data Destruction

***

### Data Encrypted for Impact

***

### Defacement

***

### Disk Content Wipe

***

### Disk Structure Wipe

***

### Endpoint Denial of Service

***

### Firmware Corruption

***

### Inhibit System Recovery

***

### Network Denial of Service

***

### Resource Hijacking

***

### Runtime Data Manipulation

***

### Service Stop

***

### Stored Data Manipulation

***

### System Shutdown/RebootTransmitted Data Manipulation

***