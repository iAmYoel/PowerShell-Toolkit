function Send-SMS {

    param(
        [ValidateScript({$_ -match "^+"})]
        [Int32]$MobilNr,

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

Här kommer ditt nya lösenord:

$Password

Mvh,
RTS Cloud Support"
    }


    Send-MailMessage @props

}

function SMS-GUI {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Send Password SMS'
    $form.Size = New-Object System.Drawing.Size(300,300)
    $form.StartPosition = 'CenterScreen'

    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(50,220)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Text = 'Send'
    $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(150,220)
    $cancelButton.Size = New-Object System.Drawing.Size(75,23)
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10,20)
    $label1.Size = New-Object System.Drawing.Size(280,20)
    $label1.Text = 'Please enter the mobile phone number:'
    $form.Controls.Add($label1)

    $textBox1 = New-Object System.Windows.Forms.TextBox
    $textBox1.Location = New-Object System.Drawing.Point(10,40)
    $textBox1.Size = New-Object System.Drawing.Size(260,20)
    $form.Controls.Add($textBox1)

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10,80)
    $label2.Size = New-Object System.Drawing.Size(280,20)
    $label2.Text = 'Please enter password:'
    $form.Controls.Add($label2)

    $textBox2 = New-Object System.Windows.Forms.TextBox
    $textBox2.Location = New-Object System.Drawing.Point(10,100)
    $textBox2.Size = New-Object System.Drawing.Size(260,20)
    $form.Controls.Add($textBox2)

    $form.Topmost = $true

    $form.Add_Shown({$textBox1.Select()})
    $form.Add_Shown({$textBox2.Select()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK){
        @{"Mobile"=$textbox1.text;"Password"=$textBox2.text}
    }
}

$Input = SMS-GUI

if ($Input.Mobile -notmatch "^\+\d*$") {
    [System.Windows.MessageBox]::Show('Mobile phone number provided is not valid','Error','Cancel','Error')
    Break
}