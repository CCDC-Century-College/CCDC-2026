$installerName = "splunkforwarder-10.0.2-windows-x64.msi"
$downloadUrl = "https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi"
$outputPath = "$env:TEMP\$installerName"

Write-Host "Downloading Splunk Universal Forwarder..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath
#Verification: Test-Path $outputPath

Write-Host "Installing silently..."
Start-Process msiexec.exe -ArgumentList "/i `"$outputPath`" /quiet RECEIVING_CI=17.20.240.20:9997 AGREETOLICENSE=Yes" -Wait
#Verification: Get-Service -Name "SplunkForwarder"