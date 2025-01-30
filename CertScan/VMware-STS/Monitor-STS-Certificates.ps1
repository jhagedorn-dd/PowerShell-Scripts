param (
    [string]$vcenterServer,
    [string]$username,
    [SecureString]$password
)

try {
    # Convert SecureString password to plaintext
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    )

    # Import VMware Module
    Import-Module VMware.VimAutomation.Cis.Core -ErrorAction Stop

    # Set PowerCLI to ignore invalid certificates
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

    # Connect to vCenter
    $connection = Connect-CisServer -Server $vcenterServer -User $username -Password $plainPassword -ErrorAction Stop

    # Function to retrieve and check STS certificate expiration
    Function Get-STSExpiry {
        try {
            $signingCertService = Get-CisService "com.vmware.vcenter.certificate_management.vcenter.signing_certificate"
            $signingCertsResponse = $signingCertService.get()

            $signingCerts = $signingCertsResponse.signing_cert_chains[0].cert_chain  # Get the first chain

            if (-not $signingCerts) {
                Write-Host "STS Expiry Check: ERROR - No STS certificate found"
                exit 3  # ERROR CODE FOR SOLARWINDS
            }

            foreach ($signingCert in $signingCerts) {
                # Convert PEM to DER format
                $certPem = $signingCert -replace "-----BEGIN CERTIFICATE-----", "" -replace "-----END CERTIFICATE-----", "" -replace "\s", ""
                $certBytes = [Convert]::FromBase64String($certPem)
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $cert.Import($certBytes)

                if ($cert.Subject -match "CN=STS") {
                    $expiryDate = $cert.NotAfter
                    $daysLeft = ($expiryDate - (Get-Date)).Days

                    if ($daysLeft -le 30) {
                        Write-Host "STS Expiry Check: CRITICAL - Expiry Date: $expiryDate | Days Left: $daysLeft"
                        exit 2  # CRITICAL
                    }
                    elseif ($daysLeft -le 60) {
                        Write-Host "STS Expiry Check: WARNING - Expiry Date: $expiryDate | Days Left: $daysLeft"
                        exit 1  # WARNING
                    }
                    else {
                        Write-Host "STS Expiry Check: OK - Expiry Date: $expiryDate | Days Left: $daysLeft"
                        exit 0  # OK
                    }
                }
            }

            Write-Host "STS Expiry Check: ERROR - No valid STS certificate found"
            exit 3  # ERROR CODE FOR SOLARWINDS

        } catch {
            Write-Host "STS Expiry Check: ERROR - $_"
            exit 3  # ERROR CODE FOR SOLARWINDS
        }
    }

    # Run the function and check STS expiry
    Get-STSExpiry

} catch {
    Write-Host "STS Expiry Check: ERROR - $_"
    exit 3  # ERROR CODE FOR SOLARWINDS
} finally {
    # Disconnect from vCenter
    if ($connection) {
        Disconnect-CisServer -Server $vcenterServer -Confirm:$false
    }
}
