$String = @"
schema version {
    version: "1"
}

machine settings {
    version: "8"
    guid: "8ca75a67-503c-4796-849f-38de00417598"
    connection-source: "preconfig"
    server-id: "0b216b55-22a6-47bd-8ef6-805f46138fda"
    connection-set-owner: "SERVE-SSL"
    connection-set-name: "nexer-connection-set"
    connection-set-last-modified: "2022-05-11 08:26:22 UTC"
    connection-set-download-host: "SERVE-SSL:ssl-ki-02"
    allow-save: "false"
    user-connection: "true"
    lock-down: "false"
    splashscreen-display: "true"
    dynamic-trust: "true"
    dynamic-connection: "true"
    eap-fragment-size: "1400"
    captive-portal-detection: "false"
    embedded-browser-saml: "false"
    enable-browser: "false"
    embedded-cef-browser-saml: "false"
    FIPSClient: "false"
    clear-smart-card-pin-cache: "false"
    block-traffic-on-vpn-disconnect: "false"
    wireless-suppression: "false"
    lockdown-exceptions-configured: "false"
}

ive "f4460527-001a-4a71-8480-1c1706ad5225" {
    friendly-name: "Nexer-Connection"
    version: "9"
    guid: "f4460527-001a-4a71-8480-1c1706ad5225"
    client-certificate-matching-rule-smartcard-logon-enabled: "false"
    client-certificate-matching-rule-eku-oid: ""
    client-certificate-matching-rule-eku-text: ""
    server-id: "0b216b55-22a6-47bd-8ef6-805f46138fda"
    connection-source: "preconfig"
    uri-list: "ssl.sigma.se/nexer"
    uri: "ssl.sigma.se/nexer"
    connection-policy-override: "true"
    connection-lock-down: "false"
    enable-stealth-mode: "false"
    show-stealth-connection: "false"
    use-for-connect: "true"
    use-for-secure-meetings: "false"
    this-server: "false"
    uri-list-use-last-connected: "false"
    uri-list-randomize: "false"
    sso-cached-credential: "false"
    connection-identity: "user"
    connection-policy: "manual"
    client-certificate-location-system: "false"
    reconnect-at-session-timeout: "true"
}
"@

$NewItem = New-Item -Path C:\Users\Public\Documents -Name nexer-component-set.pulsepreconfig -ItemType File -Value $String -Force

Start-Process "C:\Program Files (x86)\Common Files\Pulse Secure\JamUI\jamCommand.exe" -ArgumentList "/importfile $($NewItem.FullName)" -Wait

Remove-Item $NewItem -Force