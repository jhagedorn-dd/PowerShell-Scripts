$vcenterServer = Read-Host -Prompt "Enter vCenter Server"
$username = Read-Host -Prompt "Enter User"
$securePassword = Read-Host -Prompt "Enter Password" -AsSecureString

.\Monitor-STS-Certificates.ps1 -vcenterServer $vcenterServer -username $username -password $securePassword