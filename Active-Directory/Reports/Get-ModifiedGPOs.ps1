$importModule = Get-Module ActiveDirectory,GroupPolicy

$date = (Get-Date).AddMonths(-1)

$LinkedGPOs = Get-ADOrganizationalUnit -Filter * | Select-object -Property Name,DistinguishedName,@{n="LinkedGPOs";e={$_.LinkedGroupPolicyObjects | ForEach-object{$_.Substring(4,36)}}}

$result = @()
ForEach ($GPO in $LinkedGPOs.LinkedGPOs) {
    $LinkedOUs = $LinkedGPOs | where {$_.LinkedGPOs -contains $GPO}
    $result += Get-GPO -Guid $GPO | where {$_.ModificationTime.ToString('yyyy-MM') -eq $date.ToString('yyyy-MM')}| Select-object -Property DisplayName,ModificationTime,@{n="LinkedOUsName";e={$LinkedOUs.Name -join ", "}},@{n="LinkedOUsDN";e={$LinkedOUs.DistinguishedName -join ", "}}
}

$result | Export-Csv -Path C:\temp\modifiedGPOs.csv -Encoding UTF8 -Delimiter ";" -NoTypeInformation -Force