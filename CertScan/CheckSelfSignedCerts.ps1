# Define IP Range
$startIP = "192.168.0.1"
$endIP = "192.168.0.255"
$port = 443  # HTTPS Port
$outputFile = "SelfSignedCerts.csv"

# Convert IP to integer
function Convert-IPToInt($ip) {
    $bytes = $ip -split "\."
    return [int]($bytes[0]) * 16777216 + [int]($bytes[1]) * 65536 + [int]($bytes[2]) * 256 + [int]($bytes[3])
}

# Convert integer to IP
function Convert-IntToIP($int) {
    return (([math]::Floor($int / 16777216) -band 255), 
            ([math]::Floor($int / 65536) -band 255), 
            ([math]::Floor($int / 256) -band 255), 
            ($int -band 255)) -join "."
}

# Function to get SSL Certificate
function Get-SSLCertificate($ip, $port) {
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($ip, $port)
        $stream = $tcpClient.GetStream()
        
        # Create SslStream with custom validation callback to ignore certificate errors
        $sslStream = New-Object System.Net.Security.SslStream($stream, $false, { $true })
        $sslStream.AuthenticateAsClient($ip)
        
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
        $tcpClient.Close()
        return $cert
    } catch {
        Write-Host "[ERROR] $ip : $_"
        return $null
    }
}

# Function to check if certificate is self-signed
function Test-SelfSignedCertificate($cert) {
    if ($null -eq $cert) { return $false }
    return $cert.Subject -eq $cert.Issuer
}

# Function to check if certificate is expired
function Test-CertificateExpiration($cert) {
    if ($null -eq $cert) { return $false }
    return ([datetime]::Now -gt $cert.NotAfter)
}

# Initialize results array
$results = @()

# Scan IP range
$startInt = Convert-IPToInt $startIP
$endInt = Convert-IPToInt $endIP

for ($i = $startInt; $i -le $endInt; $i++) {
    $ip = Convert-IntToIP $i
    $cert = Get-SSLCertificate $ip $port
    if ($cert) {
        $isSelfSigned = Test-SelfSignedCertificate $cert
        $isExpired = Test-CertificateExpiration $cert
        $expirationDate = $cert.NotAfter
        $issuer = $cert.Issuer
        $subject = $cert.Subject

        # Determine Certificate Status
        if ($isSelfSigned) {
            $status = "SELF-SIGNED"
            Write-Host "[SELF-SIGNED] $ip - Expires on: $expirationDate" -ForegroundColor Red
        } elseif ($isExpired) {
            $status = "EXPIRED"
            Write-Host "[EXPIRED CERT] $ip - Expired on: $expirationDate" -ForegroundColor Yellow
        } else {
            $status = "VALID"
            Write-Host "[VALID CERT] $ip - Expires on: $expirationDate" -ForegroundColor Green
        }

        # Store results
        $results += [PSCustomObject]@{
            IPAddress     = $ip
            Status        = $status
            Expiration    = $expirationDate
            Issuer        = $issuer
            Subject       = $subject
        }
    }
}

# Export results to CSV
$results | Export-Csv -Path $outputFile -NoTypeInformation
Write-Host "Results saved to $outputFile" -ForegroundColor Yellow
