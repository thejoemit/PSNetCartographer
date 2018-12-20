function DownloadNMAP {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
    $wd = new-object net.webclient; 
    $wd.Headers.Add("Content-Type", "application/x-www-form-urlencoded")
    $wd.headers.Add("User-Agent", "Mozilla/4.0 (Compatible; PSNetCartographer - NMAPDropper)")
    $wd.Downloadfile("https://nmap.org/dist/nmap-7.70-win32.zip","c:\temp\nmap.zip")
    Expand-Archive c:\temp\nmap.zip -DestinationPath c:\temp\nmap\
}

function nmapTcpSubnetPortOpen {
    Param ([int] $port, [string] $ip)
    C:\temp\nmap\nmap-7.70\nmap.exe -T5 --unprivileged -p $port -sT -Pn -n --max-retries 1 --vv --open $ip
}

function nmapTcpHostPortInterrogate {
    Param ([int] $port, [string] $ip)
    C:\temp\nmap\nmap-7.70\nmap.exe -T5 --unprivileged -sT -Pn -n -sC --max-retries 1 -p $port --version-all --vv --open $ip 
}

function getLocalSubnets {
    $ips = $(Get-NetIPAddress | ? { ($_.AddressFamily -ilike "*IPv4*") -and ($_.IPAddress -notlike "127.0.0.1") -and ($_.IPAddress -notlike "169*") } | Select -ExpandProperty IPAddress)
    $cidr = $(Get-NetIPAddress | ? { ($_.AddressFamily -ilike "*IPv4*") -and ($_.IPAddress -notlike "127.0.0.1") -and ($_.IPAddress -notlike "169*") } | Select -ExpandProperty PrefixLength)
    $cnt=0
    $prefixes = @("NOT-AN-IP")*$ips.Length
    $IPv4Regex = "(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)"
    $ips | ForEach-Object {
        $ip = [system.String]::Join(" ", $($_.split(".")[0,1,2,3])) -replace ' ','.'
        if($ip -match "\A(?:${IPv4Regex})\z") {
            $range = [system.String]::Join(" ", $($_.split(".")[0,1,2])) -replace ' ','.'
            $range = "$range.0"
            $prefix = $cidr[$cnt]
            $prefix = "$range/$prefix" -replace '\s',''
            $prefixes[$cnt] = $prefix 
        }
        $cnt++
    }
    return $prefixes
}

function mapLocalSubnetsWebServers {
    getLocalSubnets | foreach {
        $network = $_ -replace '/','-'
        $starttime = Get-Date -Uformat "%H-%M-%S-%d-%m-%y"
        & nmapTcpSubnetPortOpen -port 80 -ip $_ *>> C:\temp\nmap\nmap-7.70\Local-T80-$network-$starttime.txt
        $starttime = Get-Date -Uformat "%H-%M-%S-%d-%m-%y"
        & nmapTcpSubnetPortOpen -port 443 -ip $_ *>> C:\temp\nmap\nmap-7.70\Local-T443-$network-$starttime.txt
    }
    $locals = gci -Path C:\temp\nmap\nmap-7.70\ -Recurse -Filter "*Local-*"
    $locals = $locals.Name
    $locals | foreach {
        $fpath = "C:\temp\nmap\nmap-7.70\$($_)"
        Get-Content -Path $fpath | foreach {
            if($_ -match "^[Discoverd]+[a-z\ 0-9\/\.]+$") {
                $starttime = Get-Date -Uformat "%H-%M-%S-%d-%m-%y"
                $ip = "$(($_ -split "\s+")[5])"
                $port = "$((($_ -split "\s+")[3]).ToString().Split("/")[0])"
                & nmapTcpHostPortInterrogate -ip $ip -port $port *>> C:\temp\nmap\nmap-7.70\Direct-T$port-$ip-$starttime.txt
            }
        }
    }
}
#https://jwab.net/enumerate-upnp-devices/
function upnpDevices {
    $finder = New-Object -ComObject UPnP.UPnPDeviceFinder;
    $devices = $finder.FindByType("upnp:rootdevice", 0)
    foreach($device in $devices)
    {
        Write-Host ---------------------------------------------
        Write-Host Device Name: $device.FriendlyName
        Write-Host Unique Device Name: $device.UniqueDeviceName
        Write-Host Description: $device.Description
        Write-Host Model Name: $device.ModelName
        Write-Host Model Number: $device.ModelNumber
        Write-Host Serial Number: $device.SerialNumber
        Write-Host Manufacturer Name: $device.ManufacturerName
        Write-Host Manufacturer URL: $device.ManufacturerURL
        Write-Host Type: $device.Type
    }
}
