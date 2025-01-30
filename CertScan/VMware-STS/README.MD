# SolarWinds STS Certificate Expiry Alert & Manual Renewal Documentation

## Overview
This document covers:
1. Configuring SolarWinds SAM to monitor VMware STS Certificate Expiry.
2. Setting up SolarWinds alerting based on the script.
3. Manually Renewing the STS Certificate in vCenter.
4. Troubleshooting and best practices.

---

## 1. SolarWinds STS Certificate Expiry Monitoring

### Prerequisites
- VMware PowerCLI Installed on the SolarWinds server.
- SolarWinds SAM (Server & Application Monitor) is installed and configured.
- Admin Permissions on vCenter to retrieve STS certificates.
- PowerShell Execution Policy allows running scripts.

### Step 1: Upload the Monitoring Script
1. Log into the SolarWinds Orion server.
2. Navigate to:  
   `C:\Program Files (x86)\SolarWinds\Orion\APM\Scripts\`
3. Save the PowerShell script as `Check-STS-CertExpiry.ps1`.
4. Use the following PowerShell script:

    ```powershell
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
    ```

---

## 2. Configuring SolarWinds Alerting

### Step 1: Create an Application Monitor
1. Go to **SolarWinds Orion Web Console**.
2. Click **Settings > All Settings**.
3. Under **Product Specific Settings**, select **SAM Settings**.
4. Click **Create a New Template** and name it **VMware STS Certificate Expiry Monitor**.
5. Click **Add Component Monitor** and select **Windows PowerShell Monitor**.
6. Configure the PowerShell Monitor:
   - **Script Type:** Windows PowerShell
   - **Script Body:** Copy and paste the PowerShell script.
   - **Arguments:** `-vcenterServer "your-vcenter.local" -username "admin" -password (ConvertTo-SecureString "YourPassword" -AsPlainText -Force)`
   - **Poll Interval:** Set to Daily (or as needed).
   - **Timeout:** 120 seconds.
   - **Exit Codes:**
     - `0 = OK` (More than 60 days left)
     - `1 = Warning` (30-60 days left)
     - `2 = Critical` (Less than 30 days left)
     - `3 = Error` (Certificate not found or API failure)

### Step 2: Create an Alert in SolarWinds
1. Go to **Settings > Manage Alerts**.
2. Click **Add New Alert**.
3. Name the Alert: **VMware STS Certificate Expiry Alert**.
4. **Set Trigger Condition:**
   - **Application Name:** VMware STS Certificate Expiry Monitor
   - **Component Status:** Warning / Critical
5. **Action: Send an Email/Page:**
   - **To:** admin@yourcompany.com
   - **Subject:** 🚨 VMware STS Certificate Expiry Alert: Expiring in ($DaysLeft) Days
   - **Body:**
     ```
     The VMware STS Certificate for ($vCenterServer) is expiring on ($ExpiryDate).
     Days Left: ($DaysLeft)
     Please renew the certificate immediately.
     ```
6. Save & Test.
