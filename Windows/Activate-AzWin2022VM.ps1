$azureCertificates = @(
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 03"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2003.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 03"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2003%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 04"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2004.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 04"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2004%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 05"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2005.cer" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 06"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2006.cer" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 07"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2007.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 07"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2007%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 08"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2008.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure ECC TLS Issuing CA 08"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20ECC%20TLS%20Issuing%20CA%2008%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 03"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 03"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2003%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 04"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 04"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2004%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 07"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2007.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 07"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2007%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 08"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure RSA TLS Issuing CA 08"          ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008%20-%20xsign.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure TLS Issuing CA 05"              ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2005.cer" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft Azure TLS Issuing CA 06"              ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20TLS%20Issuing%20CA%2006.cer" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft ECC Root Certificate Authority 2017"  ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20ECC%20Root%20Certificate%20Authority%202017.crt" }
    [PSCustomObject][Ordered]@{ outerText = "Microsoft RSA Root Certificate Authority 2017"  ; href = "https://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Root%20Certificate%20Authority%202017.crt" }
)

$Proxy=New-object System.Net.WebProxy
$WebSession=new-object Microsoft.PowerShell.Commands.WebRequestSession
$WebSession.Proxy=$Proxy
$testResult = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -WebSession $WebSession

if (!$testResult) {
    "Could not contact azure to check certificate."
    Exit 1
}

$attestedDoc = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/attested/document?api-version=2020-09-01" -WebSession $WebSession
$signature = [System.Convert]::FromBase64String($attestedDoc.signature)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]($signature)
$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

if($chain.Build($cert)) {
    "Cert does not need to be installed."
    Exit 0
}

$issuer = ($cert.Issuer -replace "^CN=") -replace ",.*$"

$foundCerts = $azureCertificates | where {$_.outerText -like $issuer}

New-Item -Path C:\temp -ItemType Directory -Force | Out-Null
$downloadedCerts = @()
$i=0

foreach ($item in $foundCerts) {
    $i++
    $certPath = "C:\temp\" + (($issuer -replace "\s","-") + "_$i.crt")

    try {
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $item.href -OutFile $certPath -ErrorAction Stop
        $ProgressPreference = "Continue"

        $downloadedCerts += Get-Item $certPath -ErrorAction Stop
    } catch {
        "Failed to download certificate $i"
        $downloadFailed = $true
    }
}


$i=0
foreach ($item in $downloadedCerts) {
    try {
        $item | Import-Certificate -CertStoreLocation Cert:\LocalMachine\CA -ErrorAction Stop
        $i++
        Remove-item $item -Force
    } catch {
        "Failed to install certificate '$($item.Name)'"
        $installFailed = $true
    }
}

if ($i -ge 1) {
    Start-ScheduledTask -TaskPath \Microsoft\Windows\Clip\ -TaskName LicenseImdsIntegration
}