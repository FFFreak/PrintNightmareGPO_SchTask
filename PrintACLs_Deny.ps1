<# PrintACLs_Deny.ps1
     by Danny Gorman - Coast 
  
	using ACL suggestion by TrueSec
	https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/
  
  Create the below as a SCHEDULED TASK IN a GPO with script hosted on a Domain Controller or other public network location to domain computers.
	Computer Configuration -> Preferences -> Control Panel Settings -> Scheduled tasks
	  Right click white area: New -> Scheduled task
	** ALL DEFAULTS are fine if not mentioned below.
    Run as:
		NT AUTHORITY\System
	Run whether user is Logged on or not 
		RADIAL SELECTED
	Run as Highest Privileges
		SELECTED
	Hidden
		SELECTED
	Scheduled
		Trigger 1 - Daily
			Delay up to 30 minutes
			Repeat every 1 hour for 1 day
			Enabled
		Trigger 2 - On Login
		Trigger 3 - On Startup
	Start a program
		Command: 
			C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe
		Argument: 
		    ** MODIFY BELOW COMMAND FOR YOUR NETLOGON or FILE SERVER!
			NORMAL MODE (workstations):
			-WindowStyle hidden -ExecutionPolicy bypass -NoProfile -file "\\server\share\folder\PrintACLs_Deny.ps1"
			Print Server MODE (ACLs only):
			-WindowStyle hidden -ExecutionPolicy bypass -NoProfile -file "\\server\share\folder\PrintACLs_Deny.ps1" -RunPrintServer
	Conditions
		Start only if network connection is availible (Bottom most option)
	Settings
		Allow to be ran on demand
		Run task as soon as possible after a schedule is missed.
		Stop if task runs longer than 1 hour
	
	
    TO DO: 
		Logging component to UNC path is flacky as Local SYSTEM account.. better to log to a directory...
	
	Normal / PrintServer mode:
		DENY SYSTEM WRITE to spooler drivers
	Normal:
		DENY Inbound remote connections
#>

param (
  [switch] $RunPrintServer = $false
  )

# # Settings
# Logging
$blnLogResult = $true
$LogPath = "c:\temp\"
# $LogPath = "\\server\share\folder\"
$filename = $LogPath + $($env:COMPUTERNAME) + ".txt"
# ACL path to check 
$AclPath = "C:\Windows\System32\spool\drivers"
# # END - Settings


##########################################################################
##########################################################################
# Get / Set disable Remote Inbound connections
function GetSpoolRmtConnStatusDisabled {
  $registryValue = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint").RegisterSpoolerRemoteRpcEndPoint
  if ($registryValue -eq 2) {
    return $true
  } else {
	return $False
  }
}

function SetSpoolRmtConnStatusDisabled {
  if ((test-path "HKLM:\Software\Policies\Microsoft\Windows NT\") -and (-not (test-path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\"))){
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\" -Name "Printers"
  } else {
    # Folder path exists - Do nothing
  }
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord
}

function SetSpoolRmtConnStatusEnabled {
  if ((test-path "HKLM:\Software\Policies\Microsoft\Windows NT\") -and (-not (test-path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\"))){
	# This check should never work - but left it for symmetry with the disabled function that does need it...
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\" -Name "Printers"
  } else {
	# Folder path exists - Do nothing
  }
  Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 1 -Type DWord
}
##########################################################################
##########################################################################
# Disable / Enable / Restart Spool Service
function DisableSpooler {
  param ($SpoolSrv)
  if ($SpoolSrv.StartType -ne "Disabled") {
    Set-Service -Name Spooler -StartupType Disabled
  }
  if ($SpoolSrv.Status -ne "Stopped") {
    Stop-Service -Name Spooler -Force
  }
}

function EnableSpooler {
  param ($SpoolSrv)
  if ($SpoolSrv.StartType -ne "Automatic") {
    Set-Service -Name Spooler -StartupType Automatic
  }
  if ($SpoolSrv.Status -ne "Running") {
    Start-Service -Name Spooler
  }
}

function RestartSpooler {
	param ($SpoolSrv)
	# If running -> restart.  If OFF - Leave OFF!
	if (($SpoolSrv.StartType -eq "Automatic" -or $SpoolSrv.StartType -eq "Manual") -and ($SpoolSrv.Status -eq "Running")) {
		Stop-Service -Name Spooler -Force
		Sleep 2
		Start-Service -Name Spooler
	} else {
		# Service already off, or not running
	}

	if ($SpoolSrv.Status -eq (Get-Service "spooler").status) {
	  return $true
	} else {
	  return $false
    }	
}
##########################################################################
##########################################################################
# Spool Driver Folder ACL FUNCTIONS - TrueSec ############################
function GetSpoolDriverFolderLockdown {
  param ($ACLs)
  $hasACL = $false
  $hasACL = ($ACLs.Access | ?{ $_.AccessControlType -eq "Deny" -and $_.IdentityReference -eq "NT AUTHORITY\SYSTEM"}).count -ge 1
  if ($hasACL) {
    return $true
  } else {
    # Needs ACL applied - continue
	return $false
  }	
}

function SetSpoolDriverFolderLockdown {
  param ($ACLs)
  $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
  $Acl.AddAccessRule($Ar)
  Set-Acl $AclPath $ACLs  
}
##########################################################################


##########################################################################
## Main Logic ############################################################
##########################################################################

write-host "Script Start --"
## 1. Valiate Spool Driver Folder Locked Down
$Acl = Get-Acl $AclPath
$blnFolderLockedDown = GetSpoolDriverFolderLockdown $Acl

if (-not $blnFolderLockedDown) {
  write-host "`t[1] Folder Lock Down Status: $blnFolderLockedDown" -foreground Red
  write-host "`t`tApplying Lock Down" -foreground Yellow
  # Update ACLs
  SetSpoolDriverFolderLockdown $Acl

  # Refresh
  write-host "`t`tValidating..." -foreground Yellow
  $Acl = Get-Acl $AclPath
  $blnFolderLockedDown = GetSpoolDriverFolderLockdown $Acl
  if ($blnFolderLockedDown) {
	write-host "`t`tFolder Lock Down Status: $blnFolderLockedDown" -foreground Green
  } else {
	write-host "`t`tFolder Lock Down Status: $blnFolderLockedDown" -foreground Red
  }
} else {
  # Status is good - Locked Down
  write-host "`t[1] Folder Lock Down Status: $blnFolderLockedDown" -foreground Green
}


## 2. Disable remote Connections
$blnRmtConnStatusDisabledStatus = GetSpoolRmtConnStatusDisabled
$SpoolerService = Get-Service "spooler"

if (-not $blnRmtConnStatusDisabledStatus -and -not $RunPrintServer) {
  write-host "`t[2] Disable Remote Connections: $blnRmtConnStatusDisabledStatus" -foreground Red
  write-host "`t`tApplying Disable Remote Connections" -foreground Yellow
  # Update Registry
  SetSpoolRmtConnStatusDisabled

  # Refresh
  write-host "`t`tValidating..." -foreground Yellow
  $blnRmtConnStatusDisabledStatus = GetSpoolRmtConnStatusDisabled
  if ($blnFolderLockedDown) {
	write-host "`t`tDisable Remote Connections: $blnRmtConnStatusDisabledStatus" -foreground Green
	write-host "`t`tRestarting Spooler" -foreground Green
	if (RestartSpooler $SpoolerService) {
	  write-host "`t`t`t Done." -foreground Green
	} else {
	  write-host "`t`t`r ** ERROR **" -foreground Red
    }
    # refresh 
	$SpoolerService = Get-Service "spooler"
  } else {
	write-host "`t`tDisable Remote Connections: $blnRmtConnStatusDisabledStatus" -foreground Red
  }
} elseif ($RunPrintServer){
	write-host "`t[2] Disable Remote Connections: *SKIP*" -foreground Green
	# On Print Servers do not disable in bound remove connections
	write-host "`t`tRunning with print Server mode" -foreground Green
	if (GetSpoolRmtConnStatusDisabled) {
	  # Let's repair a prior Disabled Print Server if ACLs Good!
	  if ($blnFolderLockedDown) {
		write-host "`t`tFixing Print server..." -foreground Green
  	    $blnRmtConnStatusDisabledStatus = $true
		SetSpoolRmtConnStatusEnabled

        write-host "`t`tRestarting Spooler" -foreground Green
        if (RestartSpooler $SpoolerService) {
	      write-host "`t`t`t Done." -foreground Green
	    } else {
	      write-host "`t`t`r ** ERROR **" -foreground Red
        }
		# refresh 
		$SpoolerService = Get-Service "spooler"
	  } else {
		# Leave in bad state
	  }
	} else {
	  # nothing else to do
	  $blnRmtConnStatusDisabledStatus = $true
	}
} else {
  # Status is good - Disabled
  write-host "`t[2] Disable Remote Connections: $blnRmtConnStatusDisabledStatus" -foreground Green
}


## 3. Check Spooler Status
If ($blnFolderLockedDown -and $blnRmtConnStatusDisabledStatus -and $SpoolerService.Status -eq "Running") {
  # nothing to see here - leave
  write-host "`t[3] All settings are good - Spooler running" -foreground white
  sleep 5
  exit
} elseif ($blnFolderLockedDown -and $blnRmtConnStatusDisabledStatus -and $SpoolerService.Status -ne "Running") {
  # Everything checks out - but spooler not running - lets start it.
  write-host "`t[3] All settings are good - Start Spooler" -foreground white
  EnableSpooler $SpoolerService
} else {
  # Some check did not pass - disable / Keep disabled
  write-host "`t[3] One or More settings are bad - stop Spooler" -foreground Red
  DisableSpooler $SpoolerService
}


## 4. Logging (optional)
if ($blnLogResult) {
  # Validate log location is valid
  try {
    $writeLog = $true
    $fileServer = ""
    if (-join($LogPath[0..1]) -eq "\\"){
      $fileServer = $LogPath.split("\")[2]
      if (test-connection $fileServer -Count 1) {
        # File server up
      } else {
        # File Server DOWN
	    # Omit(?) because test-connection : Testing connection to computer 'computer' failed: Error due to lack of resources - on some machines...
        $writeLog = $false
      }
    } elseif (test-path $LogPath){
      # File path good
    } else {
      # File path BAD
      $writeLog = $false
    }
  } catch { write-host "Error validating Log location" }

  try{
    # write log
    if ($blnFolderLockedDown -and $blnRmtConnStatusDisabledStatus -and $writeLog) {
	  write-host "All settings good - spooler re-enabled"
      """$(get-date)"",""success""" | set-content $filename
    } elseif ($writeLog) {
	  write-host "Some settings bad - spooler disabled"
      """$(get-date)"",""fail""" | set-content $filename
    } else {
      write-host "Error writing Log / resolving file path"
    }
  } catch { write-host "Error writing Log" }
}
write-host "-- Script End"
