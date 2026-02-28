module tspec 'templateSpec.bicep' = {
  name: 'tspec-name'
  params: {
    avdAaddsDomainName: 'domain.local'
    avdAaddsOUPath: 'CN=OU-PATH'
    avdHpName: 'avd-hp01'
    avdImageRefId: 'IMG-REF-ID'
    avdKeyVaultId: 'KEY-VAULT-ID'
    avdRgName: 'RG-Yoel-Abraham'
    avdSubnetName: 'avd-vnet01-snet01'
    avdVnetId: 'VNET-ID'
    avdVnetName: 'avd-vnet01'
    avdVnetRgName: 'RG-Yoel-Abraham'
    domainSecretName: 'avd-vmjoiner'
    domainUPN: 'yoel.abraham@rts.se'
    localSecretName: 'avd-localadmin'
    location: 'westeurope'
    vmNamePrefix: 'avd'
  }
}
