#######################
# CAMTableExport.ps1
#
# Version:      1.0
# Author:       Justin Henderson
# Requirements: Posh-SSH module installed (https://github.com/darkoperator/Posh-SSH)
#
# Description: This script is used to connect to switches and export their CAM table.
# It is useful for identifying devices plugged into a network.
Param(
  # Current supported output limited to csv or screen output
  [string]$destination = "screen",
  # Modify this array with a list of your switches
  $switches = @("10.0.0.240"),
  # If enable password is not required then set to $enable_password = ""
  $enable_password = "password",
  $maclessPortCheck = "true",
  $LogstashServer = "logingest",
  $LogstashPort = "6051"
)
Import-Module Posh-SSH
# Set $force = 1 if you want to force remove error and output files at run time
# This is only necessary if output is in a folder with other files that may not
# be generated from this script.
$force = 0

# BEGIN SCRIPT - Do not edit pass this line unless you are comfortable with scripting
if($destination -eq "file"){
    if(Get-ChildItem | Where-Object { $_.Name -notmatch "^output_" -and $_.Name -ne "error.txt" -and $_.Name -match ".txt$"}){
        $userInput = Read-Host -Prompt "Files found that do not match output files generated from this script. Continue? (y/n)"
        if($userInput -ne "y" -or $userInput -ne "Y"){
            Exit
        }
    }
}

Function Send-JsonOverTcp { 
    param ( [ValidateNotNullOrEmpty()] 
    [string] $LogstashServer, 
    [int] $Port, 
    $JsonObject) 
    $JsonString = $JsonObject -replace "`n",' ' -replace "`r",' ' -replace ' ',''
    $Ip = [System.Net.Dns]::GetHostAddresses($LogstashServer) 
    $Address = [System.Net.IPAddress]::Parse($Ip) 
    $Socket = New-Object System.Net.Sockets.TCPClient($Address,$Port) 
    $Stream = $Socket.GetStream() 
    $Writer = New-Object System.IO.StreamWriter($Stream)
    $Writer.WriteLine($JsonString)
    $Writer.Flush()
    $Stream.Close()
    $Socket.Close()
}

Remove-Item "error.txt" -ErrorAction SilentlyContinue
Remove-Item "output_*.txt" -ErrorAction SilentlyContinue

foreach($switch in $switches){
    Get-SSHSession | Remove-SSHSession | Out-Null
    $username = "admin"
    $password = "password"
    $credpassword = $password | ConvertTo-SecureString -asPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential ($username, $credpassword)
    $connect = 0
    try {
        new-object System.Net.Sockets.TcpClient($switch, "22") | Out-Null
        $connect = 1
    }
    catch {
        $connect = 0
    }
    if($connect -eq 1){
        Write-Host "Port 22 is open on $switch" -ForegroundColor Green
        if($session = New-SSHSession -AcceptKey:$true -ComputerName $switch -Credential $credentials -ConnectionTimeout 10){
            Write-Host "SSH session established to $switch" -ForegroundColor Green
            $stream = New-SSHShellStream -SSHSession $session
            if($enable_password -ne ""){
                Invoke-SSHStreamExpectAction -ShellStream $stream -Command "enable" -ExpectString "Password:" -Action "$enable_password`n" | Out-Null
            } else {
                Invoke-SSHStreamExpectAction -ShellStream $stream -Command "enable" -ExpectString "#" -Action "password`n" | Out-Null
            }
            Invoke-SSHStreamExpectAction -ShellStream $stream -Command "terminal length 0" -ExpectString "#" -Action "`n" | Out-Null
            if(Invoke-SSHStreamExpectAction -ShellStream $stream -Command "show version" -ExpectString "cisco" -Action "`n"){
                    $type = "cisco"
                }
            Invoke-SSHStreamExpectAction -ShellStream $stream -Command "show mac address-table" -ExpectString "Mac Address Table" -Action "`n" | Out-Null
            $output = ""
            Do {
                $output += $stream.Read()
                if($count -ge 1){
                    Sleep -Seconds 5
                }
                $count++
            }
            while($output -notmatch "Total Mac Address" -or $count -eq 5)
            $lines = $output -split "\n"
            $entries = @()
            foreach($line in $lines){
                if($line -match "....\.....\....." -and $line -notmatch "CPU"){
                    if($type -eq "cisco"){
                        # first column is vlan - parse with below
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $vlan = $split[0].Trim()
                        $vlanLength = $vlan.Length
                        # second column is mac address - parse with below
                        $line = $line.Substring($vlanLength)
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $mac = $split[0].Trim()
                        $macLength = $mac.Length
                        $mac = $mac -replace '\.',''
                        $mac = $mac.Substring(0,2) + ":" + $mac.Substring(2,2) + ":" + $mac.Substring(4,2) + ":" + $mac.Substring(6,2) + ":" + $mac.Substring(8,2) + ":" + $mac.Substring(10,2)
                        # third column is mac learning type - parse with below
                        $line = $line.Substring($macLength)
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $macLearningType = $split[0].ToLower().Trim()
                        $macLearningTypeLength = $macLearningType.Length
                        # fourth column is interface type and port
                        $line = $line.Substring($macLearningTypeLength)
                        $line = $line.TrimStart(" ")
                        $split = $line -split " "
                        $port = $split[0].ToLower().Trim()
                        if($port -match "^gi"){
                            $port_type = "gigabit"
                        }
                        if($port -match "^po"){
                            $port_type = "port channel"
                        }
                        $unit = $port -split "\/"
                        $unit = $unit[0] -replace '\D+(\d+)','$1'
                        $entry = New-Object -TypeName PSObject
                        $entry | Add-Member -Name "mac" -MemberType NoteProperty -Value $mac
                        $entry | Add-Member -Name "port" -MemberType NoteProperty -Value $port
                        $entry | Add-Member -Name "port_type" -MemberType NoteProperty -Value $port_type
                        $entry | Add-Member -Name "switch" -MemberType NoteProperty -Value $switch
                        $entry | Add-Member -Name "switchType" -MemberType NoteProperty -Value $type
                        $entry | Add-Member -Name "type" -MemberType NoteProperty -Value "cam_table"
                        $entry | Add-Member -Name "vlan" -MemberType NoteProperty -Value $vlan
                        $entry | Add-Member -Name "unit" -MemberType NoteProperty -Value $unit
                        $entries += $entry
                        if($destination -eq "logstash"){
                            $jsonObject = $entry | ConvertTo-Json
                            Send-JsonOverTcp $LogstashServer $LogstashPort $jsonObject
                        }
                    }
                }
            }
            if($maclessPortCheck -eq "true"){
                if($type -eq "cisco"){
                    Invoke-SSHStreamExpectAction -ShellStream $stream -Command "show interface status" -ExpectString "Port" -Action "`n" | Out-Null
                    $output = $stream.Read()
                    $lines = $output -split "\n"
                    $activePorts = @()
                    foreach($line in $lines){
                        if($line -match "connected"){
                            $line = $line.TrimStart(" ")
                            $split = $line -split " "
                            $port = $split[0].ToLower().Trim()
                            $entry = New-Object -TypeName PSObject
                            $entry | Add-Member -Name "port" -MemberType NoteProperty -Value $port
                            $activePorts += $entry
                        }
                    }
                }
                # Find port-channel members as these show as active but CAM table entry is assigned
                # to the port-channel rather than individual ports
                if(Invoke-SSHStreamExpectAction -ShellStream $stream -Command 'show running-config | include Port-channel' -ExpectString "interface" -Action "`n"){
                    $output = $stream.Read()
                    $lines = $output -split "\n"
                    $channelPorts = @()
                    foreach($line in $lines){
                        if($line -match "Port-channel\d\d"){
                            $channelPort = $line -replace '\D+(\d+)','$1'
                            $channelPort = $channelPort.Trim()
                            if(Invoke-SSHStreamExpectAction -ShellStream $stream -Command "show interfaces port-channel $channelPort controller | include Members" -ExpectString "Members in this channel: " -Action "`n"){
                                #Sleep -Seconds 2
                                $channelMembers = $stream.Read()
                                $channelMembers = $channelMembers.ToLower() -split " "
                                foreach($channelPort in $channelMembers){
                                    if($channelPort -match "\d+\/\d+"){
                                        $channelPorts += $channelPort
                                    }
                                }
                            }
                        }
                    }
                }

                # Check if port is in $activePorts but not in $entries. If so then the
                # port is active mut does not have an entry in the CAM table
                $maclessPorts = @()
                foreach($port in $activePorts.port){
                    # Find any active ports that are not in the CAM table    
                    if($entries.port -notcontains $port){
                        # Remove any ports that are members of a channel-group as they will
                        # not have CAM table entries by design
                        if($port -notin $channelPorts){
                            $entry = New-Object -TypeName PSObject
                            $entry | Add-Member -Name "mac" -MemberType NoteProperty -Value $mac
                            $entry | Add-Member -Name "type" -MemberType NoteProperty -Value "cam_table_macless_port"
                            $maclessPorts += $entry
                            if($destination -eq "logstash"){
                                $jsonObject = $entry | ConvertTo-Json
                                Send-JsonOverTcp $LogstashServer $LogstashPort $jsonObject
                            }
                        }
                    }
                }
            }
            if($destination -eq "file"){
                $entries | Export-Csv -Path "output_$switch.txt" -Force -NoTypeInformation
            }
            if($destination -eq "screen"){
                Write-Host "The following ports have CAM table entries" -ForegroundColor Cyan
                $entries | ft
            }
            if($maclessPortCheck -eq "true"){
                if($destination -eq "file"){
                    $maclessPorts | Export-Csv -Path "macless_$switch.txt" -Force -NoTypeInformation
                }
                if($destination -eq "screen"){
                    Write-Host "The below ports are active but do not have CAM table entries." -ForegroundColor Cyan
                    Write-Host "This can be due to wake-on-lan or an interace listening in promiscuous mode" -ForegroundColor Cyan
                    $maclessPorts
                }
            }
            Get-SSHSession | Remove-SSHSession | Out-Null
        } else {
            Write-Host "Unable to connect to $switch" -ForegroundColor Red
            Write-Output "Unable to connect to $switch" | Out-File error.txt -Append -Force
        }
    } else {
        Write-Host "Port 22 is not open on $switch" -ForegroundColor Red
        Write-Output "Port 22 is not open on $switch" | Out-File error.txt -Append -Force
    }
}