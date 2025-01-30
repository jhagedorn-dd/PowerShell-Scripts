# Define Input and Output CSV File Paths
$InputCSV = ".\Input.csv"
$OutputCSV = ".\Results.csv"

# Import the CSV
$CertData = Import-Csv -Path $InputCSV

# Initialize an array to store results
$Results = @()

# Define all certificate store locations
$CertStores = @("LocalMachine", "CurrentUser")

# Define possible sub-stores
$SubStores = @("My", "Root", "CA", "AuthRoot", "TrustedPeople", "TrustedPublisher", "Disallowed")

# Loop through each computer in the CSV
foreach ($entry in $CertData) {
    $ComputerName = $entry.ComputerName

    foreach ($Store in $CertStores) {
        foreach ($SubStore in $SubStores) {
            $CertPath = "Cert:\$Store\$SubStore"
            try {
                # Retrieve certificates from each store
                $Certs = Get-ChildItem -Path $CertPath -ErrorAction Stop

                foreach ($Cert in $Certs) {
                    # Check if the certificate is Self-Signed (Issuer = Subject)
                    $IsSelfSigned = ($Cert.Issuer -eq $Cert.Subject)

                    # Add data to results array
                    $Results += [PSCustomObject]@{
                        ComputerName  = $ComputerName
                        CertStore     = "$Store\$SubStore"
                        Thumbprint    = $Cert.Thumbprint
                        Subject       = $Cert.Subject
                        Issuer        = $Cert.Issuer
                        Expiration    = $Cert.NotAfter
                        IsSelfSigned  = $IsSelfSigned
                    }
                }
            } catch {
                Write-Warning "Failed to access $CertPath on $ComputerName"
            }
        }
    }
}

# Export results to CSV
$Results | Export-Csv -Path $OutputCSV -NoTypeInformation

Write-Host "Self-Signed SSL certificate scan completed. Results saved to: $OutputCSV"
