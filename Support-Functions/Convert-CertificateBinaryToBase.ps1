function Convert-CertificateBinaryToBase64 {
    param( [string]$SourceFile, [string]$DestinationFile )
    $cert = get-content "$SourceFile" -Encoding Byte
    $content = @(
      '-----BEGIN CERTIFICATE-----'
      [System.Convert]::ToBase64String($cert, 'InsertLineBreaks')
      '-----END CERTIFICATE-----'
    )
    $content #| Out-File -FilePath "$DestinationFile" -Encoding ASCII
  }