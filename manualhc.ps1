
$h = hostname
$YY = (get-date).year
$MM1 = (get-date).month
$DD = (get-date).day
$HH = (get-date).hour
$MM2 = (get-date).Minute
$dddd = $("$YY" + "_" + "$MM1" + "_" + "$DD" + "-" + "$HH" + ":" + "$MM2")

##### BUSINESS NOTICE ##########
$path_a1 = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system"
$reg_a1 = $("Registry::"+$path_a1)
$key_a1 = "legalnoticecaption"
$bn1 = Get-Item -Path $reg_a1 | findstr.exe $key_a1

$path_a2 = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system"
$reg_a2 = $("Registry::"+$path_a2)
$key_a2 = "legalnoticetext"
$bn2 = Get-Item -Path $reg_a2 | findstr.exe $key_a2 | Format-Table wide


##### OS RESOURCES ##############
$a1 = "c:\Windows"
$a2 = "c:\Windows\Security"
$a3 = "c:\Windows\System"
$a4 = "c:\Windows\System32"
$a5 = "c:\Windows\system32\config"
$a6 = "c:\Windows\system32\drivers"
$a7 = "c:\Windows\system32\spool"
$a8 = "c:\Windows\system32\GroupPolicy"
$a9 = "c:\Windows\WinSxS\Backup"
$a10 = "c:\Windows\boot"
$a11 = "c:\Windows\system32\winload.exe"
$a12 = "c:\bootmgr"
$a13 = "c:\AUTOEXEC.BAT"
$a14 = "c:\Windows\syswow64"
$a15 = "c:\Windows\syswow64\drivers"
$a16 = "c:\Windows\System32\Winevt\Logs\Security.evtx"
$a17 = "c:\Windows\System32\Winevt\Logs\DNS Server.evtx"
$a18 = "c:\Windows\system32\config\SecEvent.Evt"

$acl1=Get-Acl $a1 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl2=Get-Acl $a2 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl3=Get-Acl $a3 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl4=Get-Acl $a4 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl5=Get-Acl $a5 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl6=Get-Acl $a6 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl7=Get-Acl $a7 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl8=Get-Acl $a8 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl9=Get-Acl $a9 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl10=Get-Acl $a10 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl11=Get-Acl $a11 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl12=Get-Acl $a12 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl13=Get-Acl $a13 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync" 
$acl14=Get-Acl $a14 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl15=Get-Acl $a15 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl16=Get-Acl $a16 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl17=Get-Acl $a17 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"
$acl18=Get-Acl $a18 -ErrorAction SilentlyContinue | Select -ExpandProperty Access | ft IdentityReference,FileSystemRights | findstr "Read Full Modify Sync"

############## REGISTRY
$classes = get-acl -Path Registry::hkey_classes_root | select -ExpandProperty Access | ft IdentityReference,RegistryRights
$security = get-acl -Path Registry::HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security  | select -ExpandProperty Access | ft IdentityReference,RegistryRights

$evt_app = Get-Item -Path Registry::HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application -ErrorAction SilentlyContinue | findstr.exe RestrictGuestAccess
$evt_sec = Get-Item -Path Registry::HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security -ErrorAction SilentlyContinue | findstr.exe RestrictGuestAccess
$evt_sys = Get-Item -Path Registry::HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System -ErrorAction SilentlyContinue | findstr.exe RestrictGuestAccess
$evt_dns = Get-Item -Path Registry::"HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\DNS Server" -ErrorAction SilentlyContinue | findstr.exe RestrictGuestAccess
$lsa = Get-Item -Path Registry::HKLM\SYSTEM\CurrentControlSet\control\lsa -ErrorAction SilentlyContinue | findstr.exe "crashonauditfail"
$exp = Get-Item -Path Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\ -ErrorAction SilentlyContinue | findstr.exe "NoDriveTypeAutoRun"


$opt1 = "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
$reg_a1 = $("Registry::"+$opt1)
$key_a1 = "AutoBackupLogFiles"
$a1opt = Get-Item -Path $reg_a1 | findstr.exe $key_a1

$opt2 = "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System"
$reg_a2 = $("Registry::"+$opt2)
$key_a2 = "AutoBackupLogFiles"
$a2opt = Get-Item -Path $reg_a2 | findstr.exe $key_a2

$opt3 = "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application"
$key_a3 = "AutoBackupLogFiles"
$reg_a3 = $("Registry::"+$opt3)
$a3opt = Get-Item -Path $reg_a3 | findstr.exe $key_a3

$opt4 = "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
$key_a4 = "Retention"
$reg_a4 = $("Registry::"+$opt4)
$a4opt = Get-Item -Path $reg_a4 | findstr.exe $key_a4

$opt5 = "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System"
$key_a5 = "Retention"
$reg_a5 = $("Registry::"+$opt5)
$a5opt = Get-Item -Path $reg_a5 | findstr.exe $key_a5

$opt6 = "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application"
$key_a6 = "Retention"
$reg_a6 = $("Registry::"+$opt6)
$a6opt = Get-Item -Path $reg_a6 | findstr.exe $key_a6


###################################FUNCTIONS#################################################

function displaybn{
    #OUTPUT FOR BUSINESS NOTICE
    clear
    echo ""
    echo ""
    echo "=============================="
    echo "SERVER COMPLIANCE TEAM"
    echo "MANUAL HEALTH CHECK FOR LEGAL NOTICES"
    echo "HOSTNAME: $h"
    echo "DATE: $dddd"
    echo "PAGE 1 of 1"
    echo "=============================="
    echo "REGISTRY VALUES"
    echo ""
    echo $path_a1
    if ($bn1){
    $bn1 = $bn1 -replace "legalnoticecaption            : ",""
    echo $bn1
    } else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
    echo ""
    echo $path_a2
    if ($bn2){
    $bn2 = $bn2 -replace "                               legalnoticetext               : ",""
    echo $bn2
    } else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
    echo ""
    echo "========== END OF OUTPUT FOR LEGAL NOTICES =========="
    echo ""

    $cont = Read-Host "Press ENTER to go back to Home Page"
    if($cont){
    step1
    $cont=""
    }
}

function displayos{
#OUTPUT MANUAL HEALTH CHECK FOR OS RESOURCES
clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR OS RESOURCES"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 1 of 5"
echo "=============================="
echo "Operating System Resources"
echo ""
echo "PERMISSION FOR $a1"
if ($acl1){echo $acl1.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a2"
if ($acl2){echo $acl2.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a3"
if ($acl3){echo $acl3.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a4"
if ($acl4){echo $acl4.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR OS RESOURCES"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 2 of 5"
echo "=============================="
echo "PERMISSION FOR $a5"
if ($acl5){echo $acl5.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a6"
if ($acl6){echo $acl6.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a7"
if ($acl7){echo $acl7.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a8"
if ($acl8){echo $acl8.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR OS RESOURCES"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 3 of 5"
echo "=============================="
echo "PERMISSION FOR $a9"
if ($acl9){echo $acl9.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a10"
if ($acl10){echo $acl10.Trim()
echo "---- LIST DIRECTORY ---"
$boot = dir $a10
echo $boot
} 
else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a11"
if ($acl11){echo $acl11.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a12"
if ($acl12){echo $acl12.Trim()
}else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR OS RESOURCES"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 4 of 5"
echo "=============================="
echo "PERMISSION FOR $a13"
if ($acl13){echo $acl13.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a14"
if ($acl14){echo $acl14.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a15"
if ($acl15){echo $acl15.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a16"
if ($acl16){echo $acl16.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR OS RESOURCES"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 5 of 5"
echo "=============================="
echo "PERMISSION FOR $a17"
if ($acl17){echo $acl17.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "PERMISSION FOR $a18"
if ($acl18){echo $acl18.Trim()} else{echo "FILE/FOLDER NOT FOUND IN THIS SERVER"}
echo ""
echo "========== END OF OUTPUT FOR OS RESOURCES =========="
echo ""

    $cont = Read-Host "Press ENTER to go back to Home Page"
    if($cont){
    step1
    $cont=""
    }
}

function displayreg{
#OUTPUT FOR REGISTRY
clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR SYSTEM REGISTRY"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 1 of 3"
echo "=============================="
echo "HKEY_CLASS_ROOT PERMISSION"
echo $classes
echo "=============================="
echo "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security PERMISSION"
echo $security
echo "=============================="
echo ""

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR SYSTEM REGISTRY"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 2 of 3"
echo "=============================="
echo "MANDATORY REGISTRY VALUES"
echo ""
echo "Registry::HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Application\RestrictGuestAccess"
echo $evt_app.Trim()
echo ""
echo "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security\RestrictGuestAccess"
echo $evt_sec.Trim()
echo ""
echo "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\System\RestrictGuestAccess"
echo $evt_sys.Trim()
echo ""
echo "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\DNS Server\RestrictGuestAccess"
if ($evt_dns){echo $evt_dns.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo "HKLM\SYSTEM\CurrentControlSet\control\lsa\crashonauditfail"
echo $lsa.Trim()
echo ""
echo "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun"
echo $exp.Trim()
echo ""
echo "=============================="
echo ""

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

clear
echo ""
echo ""
echo "=============================="
echo "SERVER COMPLIANCE TEAM"
echo "MANUAL HEALTH CHECK FOR SYSTEM REGISTRY"
echo "HOSTNAME: $h"
echo "DATE: $dddd"
echo "PAGE 3 of 3"
echo "=============================="
echo "OPTIONAL REGISTRY VALUES"
echo ""
echo $opt1
if ($a1opt){echo $a1opt.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo $opt2
if ($a2opt){echo $a2opt.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo $opt3
if ($a3opt){echo $a3opt.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo $opt4
if ($a4opt){echo $a4opt.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo $opt5
if ($a5opt){echo $a5opt.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo $opt6
if ($a6opt){echo $a6opt.Trim()} else{echo "REGISTRY KEY NOT FOUND IN THIS SERVER"}
echo ""
echo "=============================="

    $cont = Read-Host "Press ENTER to go back to Home Page"
    if($cont){
    step1
    $cont=""
    }

}

function step1{    
        clear; echo ""; echo "";
        echo "============================================"
        echo "SERVER COMPLIANCE TEAM"
        echo "MANUAL HEALTH CHECK SCRIPT"
        echo ""
        echo "IMPORTANT: This script has been tested to "
        echo "work for Windows Server 2012 R2"
        echo "Last Updated: 2018 June 12"
        echo ""
        echo "Coverage:"
        echo "1. Business/Legal Notice"
        echo "2. OS Resources"
        echo "3. Mandatory & Optional Registry Settings"
        echo ""
        $h = hostname
        $ip = ipconfig | findstr "IPv4"
        $ip = $ip -replace "IPv4 Address. . . . . . . . . . . : ",""
        $wanip = Invoke-RestMethod http://ipinfo.io/json | Select -exp ip
        echo "You are checking $h"
        echo "LAN IP Address: $ip"
        echo "WAN IP Address: $wanip"
        echo ""
        echo "============================================"
        echo ""
        echo ""

        $mainchoice = Read-Host "Enter the HC result you want to view "
        echo  $mainchoice
        #if($mainchoice -ne "1" -OR $mainchoice -ne "2" -OR $mainchoice -ne "3")
        #{step1}else{
        if($mainchoice -eq "1"){displaybn}
        if($mainchoice -eq "2"){displayos}
        if($mainchoice -eq "3"){displayreg}
        if($mainchoice -ne "1" -OR $mainchoice -ne "2" -OR $mainchoice -ne "3")
        {step1}
        #}

}

step1
