$udp = New-Object System.Net.Sockets.UdpClient
$target = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse("127.0.0.1"), 9999)

for ($i = 0; $i -lt 8000; $i++) {
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("attack")
    $udp.Send($bytes, $bytes.Length, $target) | Out-Null
}

Write-Output "Flood sent"
