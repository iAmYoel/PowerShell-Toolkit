#Install-Module MSOnline
#Connect-MsolService -Credential (Get-Credential)

$ADUsers = @()
$AzureUsers = @()

Get-ADUser -Filter * -Properties ObjectGUID | sort | select Name,SamAccountName,UserPrincipalName,ObjectGUID | ForEach-Object{
    
    Clear-Variable UserImmutableID,MsolUser -ErrorAction SilentlyContinue

    $UserImmutableID = [system.convert]::ToBase64String(([GUID]($_.ObjectGUID)).tobytearray())

    IF($_.UserPrincipalName){$MsolUser = Get-MsolUser -UserPrincipalName $_.UserPrincipalName -ErrorAction SilentlyContinue}

    IF($MsolUser){
        $ADUsers += $_ | Select -Property Name,SamAccountName,UserPrincipalName,@{Name="ImmutableID";Expression={$UserImmutableID}}
        #$MsolUser | Set-MsolUser -ImmutableId $UserImmutableID -Verbose
    }

}

$ADUsers | foreach{$AzureUsers += Get-MsolUser -UserPrincipalName $_.UserPrincipalName | select -Property DisplayName,UserPrincipalName,ImmutableID}

$ADUsers | Format-Table -Wrap -AutoSize
$AzureUsers | Format-Table -Wrap -AutoSize