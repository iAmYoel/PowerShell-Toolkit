@description('AVD host pool ')
param hpName string

@description('AVD host pool location')
param hpLocation string

@description('AVD host pool friendly name')
param hpFriendlyName string

@description('AVD host pool type')
param hpType string

@description('AVD host pool load balancer type')
param hpLBType string

@description('AVD host pool preferred app group type')
param hpAppGroupType string

@description('AVD Workspace name')
param hpWsName string

@description('AVD Workspace Friendly name')
param hpWsFriendlyName string

@description('AVD Workspace Description')
param hpWsDescription string

@description('AVD Workspace Description')
param hpMaxSessionLimit int = 20

//##########################################################################################


resource avdHostPool 'Microsoft.DesktopVirtualization/hostPools@2022-09-09' = {
  name: hpName
  location: hpLocation
  properties: {
    friendlyName: hpFriendlyName
    hostPoolType:  hpType
    loadBalancerType: hpLBType
    preferredAppGroupType: hpAppGroupType
    maxSessionLimit: hpMaxSessionLimit
  }
}

resource workSpace 'Microsoft.DesktopVirtualization/workspaces@2022-09-09' = {
  name: hpWsName
  location: hpLocation
  properties: {
    friendlyName: hpWsFriendlyName
    description: hpWsDescription
  }
}

output avdHpName string = avdHostPool.name
output avdHpId string = avdHostPool.id
output avdHostPool object = avdHostPool
