function Send-SMS {

    param(
        [parameter(Mandatory)]
        [ValidateScript({$_ -match "^+"})]
        [String]$MobilNr = "",

        [String]$Password
    )

    $props = @{
        From = "support@rts.se"
        To = "$MobilNr@qlnk.se"
        SmtpServer = "smtprelay.rts.se"
        Port = 25
        Subject = " "
        Encoding = [System.Text.Encoding]::UTF8
        Body = "Hej,

Här kommer ditt nya lösenord.

$Password

Mvh,
RTS Support"
    }


    Send-MailMessage @props

}