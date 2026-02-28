resource aaddsDomain 'Microsoft.AAD/domainServices@2022-12-01' = {
  name: ''
  location: ''
  properties: {
    domainName: ''
    filteredSync: 'Disabled'
    domainConfigurationType: 'FullySynced'
    notificationSettings: {
      notifyGlobalAdmins: 'Enabled'
      notifyDcAdmins: 'Enabled'
      additionalRecipients: []
    }
    replicaSets: [
      {
        subnetId:
        location:''
      }
    ]
    domainSecuritySettings: {
      tlsV1: 'Enabled'
      ntlmV1: 'Disabled'
      syncNtlmPasswords: 'Enabled'
      syncOnPremPasswords: 'Enabled'
      kerberosRc4Encryption: 'Enabled'
      kerberosArmoring: 'Disabled'
    }
    sku: 'standard'
  }
}
