# This PowerShell script is for PERSONAL use with Windows 10 Home and Professional installations.
#
# LIFE IS GRAND IN OUR TOWN
#              - Microsoft, 2021
#
# Objective: make Windows 10 tolerable and a bit safer
# Use:       run PowerShell as Admin 
#            (lazy: copy-and-paste into PowerShell Administrator window)

##########

# Power Optimizations

Write-Host "Optimizing power settings"

# Removing Sleep from Power menu

Write-Host "Removing Sleep from Power menu"
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force | Out-Null
	}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0

# Disabling sleep and drive spindown

Write-Host "Disabling sleep and drive spindown"
# Power Config details: https://ss64.com/nt/powercfg.html
powercfg /x -hibernate-timeout-ac 0
powercfg /x -hibernate-timeout-dc 0
powercfg /x -disk-timeout-ac 0
powercfg /x -disk-timeout-dc 0
powercfg /x -monitor-timeout-ac 0
powercfg /x -monitor-timeout-dc 0
powercfg /x -standby-timeout-ac 0
powercfg /x -standby-timeout-dc 0

# Disabling Fast Startup (Hibernate-Hybrid Boot)

Write-Host "Disabling Fast Startup (Hibernate-Hybrid Boot)"
If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power")) {
	New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force | Out-Null
	}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0


##########

# Load Default User profile, for propagations to future user accounts

Write-Host "Loading Default-User Registry Hive..."
REG LOAD HKEY_Users\DEFAULTY "C:\Users\Default\NTUSER.DAT" | Out-Null
Start-Sleep -s 2
Write-Host "Default-User Registry Hive Loaded"

##########

# Desktop - Remove All Shortcuts

Write-Host "Desktop - Removing All Shortcuts"
Get-ChildItem $env:USERPROFILE\Desktop\*.lnk | ForEach-Object { Remove-Item $_ }
Get-ChildItem $env:Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ }

##########

# Explorer - Add Recycle Bin to sidebar

Write-Host "Explorer - Add Recycle Bin to sidebar"
If (!(Test-Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}")) {
	New-Item -Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Force | Out-Null
	}
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1

If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1

##########

# Programs - Removing pre-installed MS bloatware from current and all future user accounts

Write-Host "Removing pre-installed MS bloatware"
$AppsList = "Microsoft.BingFinance","Microsoft.BingNews","Microsoft.BingWeather","Microsoft.XboxApp","Microsoft.SkypeApp","Microsoft.MicrosoftSolitaireCollection","Microsoft.BingSports","Microsoft.ZuneMusic","Microsoft.ZuneVideo","Microsoft.People","Microsoft.MicrosoftOfficeHub","Microsoft.WindowsMaps","microsoft.windowscommunicationsapps","Microsoft.Getstarted","Microsoft.3DBuilder","Microsoft.549981C3F5F10","Microsoft.Office.OneNote","Microsoft.WindowsAlarms","Microsoft.3dbuilder","Microsoft.Microsoft3DViewer","Microsoft.WindowsCamera","Microsoft.GetHelp","Microsoft.WindowsFeedbackHub","Microsoft.MixedReality.Portal","Microsoft.MicrosoftStickyNotes","Microsoft.WindowsSoundRecorder","Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider","XboxOneSmartGlass","Microsoft.XboxSpeechToTextOverlay","Microsoft.XboxGameOverlay","Microsoft.Xbox.TCUI","Microsoft.YourPhone","Microsoft.WindowsPhone","Microsoft.CommsPhone","Microsoft.Asphalt8Airborne","king.com.CandyCrushSodaSaga","Facebook","Todos","Microsoft.Whiteboard","MinecraftUWP","PandoraMediaInc","Netflix","Office.Sway","9E2F88E3.Twitter","Microsoft.Messaging","Microsoft.OneConnect","AutodeskSketchBook","SpotifyAB.SpotifyMusic","Microsoft.Wallet","Microsoft.FreshPaint"
ForEach ($App in $AppsList)
{
	$PackageFullName = (Get-AppxPackage $App).PackageFullName
	$ProPackageFullName = (Get-AppxProvisionedPackage -online | Where-Object {$_.Displayname -eq $App}).PackageName
	# Write-Host $PackageFullName
	# Write-Host $ProPackageFullName
	if ($PackageFullName)
	{
		Write-Host "Removing Package: $App"
		remove-AppxPackage -package $PackageFullName | Out-Null
	}
	else
	{
		Write-Host "Unable to find package: $App"
	}
	if ($ProPackageFullName)
	{
		Write-Host "Removing Provisioned Package: $ProPackageFullName"
		Remove-AppxProvisionedPackage -online -packagename $ProPackageFullName | Out-Null
	}
	else
	{
		Write-Verbose "Unable to find provisioned package: $App"
	}
}


##########

Write-Host "Starting registry edits..."

# Start - Remove Recently Added Section

Write-Host "Start - Remove Recently Added Section"
If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
	New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
	}
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Policies\Microsoft\Windows\Explorer")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1


##########

# Start - Remove All Pinned Tiles 

Write-Host "Start - Remove All Pinned Tiles"

# First, from the .default user
Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"

# Deleting layout file if it already exists
If(Test-Path $layoutFile){Remove-Item $layoutFile}

# Creating blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

# Assigning start layout
# force it to apply with "LockedStartLayout" at both machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    IF(!(Test-Path -Path $keyPath)) { 
        New-Item -Path $basePath -Name "Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}


Start-Sleep -s 3

# Enable the ability to pin items again
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

# Delete layout file, make clean start menu default for all new users

Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\
Remove-Item $layoutFile


##########


# Taskbar - Disable Notification Center Badge Count 

Write-Host "Taskbar - Disable Notification Center Badge Count"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /V NOC_GLOBAL_SETTING_GLEAM_ENABLED /T REG_DWORD /D 0 /F | Out-Null
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /V NOC_GLOBAL_SETTING_BADGE_ENABLED /T REG_DWORD /D 0 /F | Out-Null
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_GLEAM_ENABLED" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_BADGE_ENABLED" -Type DWord -Value 0


##########

# Taskbar - Remove Type Here To Search Bar

Write-Host "Taskbar - Remove Type Here To Search Bar"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Search")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0


##########

# Taskbar - Remove Cortana Button

Write-Host "Taskbar - Remove Cortana Button"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0


##########

# Taskbar - Remove Task View Button

Write-Host "Taskbar - Remove Task View Button"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0


##########

# Taskbar - Show all Systray Icons

Write-Host "Taskbar - Show all Systray Icons"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0


##########

# Taskbar - Show all Application Titles

Write-Host "Taskbar - Show all Application Titles"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1


##########

# Taskbar - Remove Meet Now Icon

Write-Host "Taskbar - Remove Meet Now Icon"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1


##########

# Program - Remove OneDrive

Write-Host "Removing OneDrive"
Write-Host "NOTE: This can take up to 1 minute"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue -Force
Start-Sleep -s 2
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $onedrive)) {
	$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Start-Sleep -s 2
Stop-Process -Name "explorer" -ErrorAction SilentlyContinue -Force
Start-Sleep -s 2
Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Old method:
# taskkill /f /im OneDrive.exe
# C:\Windows\SysWOW64\OneDriveSetup.exe /uninstall


##########

# Program - Remove Cortana while preserving search

Write-Host "Remove Cortana while preserving search"
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Personalization\Settings" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0


##########

# Explorer - Show all File Extensions

Write-Host "Explorer - Show all File Extensions"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0


##########

# Security - Disable Excessive Windows Security Notifications

Write-Host "Disable Excessive Windows Security Notifications"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Force | Out-Null
	}
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableNotifications" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -Name "DisableEnhancedNotifications" -Type DWord -Value 1

##########

# Core - Disable Windows Update automatic restart

Write-Host "Disable Windows Update automatic restart"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1


##########

# Core - Disable Telemetry

Write-Host "Disable Telemetry"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0


##########

# Core - Disable Privacy Settings Experience

Write-Host "Disable Privacy Settings Experience"
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 1


##########

# Core - Disable Location Tracking Metrics

Write-Host "Disable Location Tracking Metrics"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0

##########

# Core - Disable Feedback Prompts

Write-Host "Disable Feedback Prompts"
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0


##########

# Core - Disable Advertising ID Tracking

Write-Host "Disable Advertising ID Tracking"
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0


##########

# Core - Disable Sticky keys prompt

Write-Host "Disable Sticky keys prompt"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"


##########

# Start - Disable Bing Search in Start Menu

Write-Host "Disable Bing Search in Start Menu"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Search")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0


##########

# Core - Set Windows to 24-hour time and ISO Date 

Write-Host "Set Windows to 24-hour time and ISO Date"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sLongDate -Value "dddd, d MMMM, yyyy"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "yyyy-MM-dd"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortTime -Value "HH:mm"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sYearMonth -Value "MMMM yyyy"
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International" -Name "sLongDate" -Type String -Value "dddd, d MMMM, yyyy"
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International" -Name "sShortDate" -Type String -Value "yyyy-MM-dd"
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International" -Name "sShortTime" -Type String -Value "HH:mm"
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International" -Name "sTimeFormat" -Type String -Value "HH:mm:ss"
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\Control Panel\International" -Name "sYearMonth" -Type String -Value "MMMM yyyy"


##########

# Core - Set Windows to Dark Mode

Write-Host "Set Windows to Dark Mode"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f | Out-Null
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f | Out-Null
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f | Out-Null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f | Out-Null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f | Out-Null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f | Out-Null
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f | Out-Null
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f | Out-Null
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f | Out-Null
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f | Out-Null
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f | Out-Null
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Name "AppsUseLightTheme" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" -Name "SystemUsesLightTheme" -Type DWord -Value 0
If (!(Test-Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize")) {
	New-Item -Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Force | Out-Null
	}
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
Set-ItemProperty -Path "Registry::HKEY_USERS\DEFAULTY\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

##########

# Disable Windows HI OOBE Animations

Write-Host "Disable Windows HI OOBE Animations"
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Type DWord -Value 0

##########

# Set Explorer Folders in Start Menu

Write-Host "Set Explorer Folders in Start Menu"

# NOTE: To force a pinned folder to be visible, 
# set the corresponding registry values to 1 (both values must set).
# To force it to be hidden, set the "_ProviderSet" value to 1 
# and the other one to 0; to let the user choose "_ProviderSet" 
# value to 0 or delete the values.

If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start")) {
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Force | Out-Null
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderFileExplorer" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderFileExplorer_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPersonalFolder" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPersonalFolder_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderSettings" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderSettings_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderNetwork" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderNetwork_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDocuments" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDocuments_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDownloads" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderDownloads_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPictures" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderPictures_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderMusic" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderMusic_ProviderSet" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderVideos" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start" -Name "AllowPinnedFolderVideos_ProviderSet" -Type DWord -Value 1

##########

# Remove Edge Pin
If (Test-Path "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge*") {
	Write-Host "Edge Pin detected, attempting removal of aliases and regkeys now..."
	Start-Sleep -s 2
	# waiting for other first-login actions to finish
	Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge*" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Edge" -Name "TaskbarAutoPin" -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}" -Force -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -Force -ErrorAction SilentlyContinue
   }

##########

# Unload Default User profile hive to apply to future profiles

Write-Host "Unloading Default User profile hive to apply to future profiles"
Start-Sleep -s 2
[GC]::Collect()
Start-Sleep -s 2
REG UNLOAD HKEY_Users\DEFAULTY | Out-Null
Start-Sleep -s 2
Write-Host "Default-User Registry Hive Unloaded"

##########

Stop-Process -Force -Name explorer #restart Explorer to take changes

Write-Host "DONE — PLEASE REVIEW ABOVE, CLOSE THIS WINDOW, THEN REBOOT"
