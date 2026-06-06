targetScope = 'resourceGroup'

@description('Short lowercase prefix used for Azure resource names.')
@minLength(3)
@maxLength(17)
param resourcePrefix string

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Azure region for Static Web Apps. Static Web Apps is not available in every Azure region.')
param staticWebAppLocation string = 'eastus2'

@description('Azure region for Cosmos DB. Keep separate because new subscriptions may hit regional capacity limits.')
param cosmosLocation string = 'eastus2'

@description('Azure region for the Azure Functions app. Keep separate because App Service quota can vary by region.')
param functionAppLocation string = 'centralus'

@description('Deploy the Azure Functions compute plan and API host. Set false when the subscription has no compute quota yet.')
param deployFunctionApp bool = false

@description('Deploy Azure Static Web Apps hosting. Set true after repositoryUrl is configured.')
param deployStaticWebApp bool = false

@description('Git repository URL used by Azure Static Web Apps when deployStaticWebApp is true.')
param staticWebAppRepositoryUrl string = ''

@description('Git branch used by Azure Static Web Apps when deployStaticWebApp is true.')
param staticWebAppBranch string = 'main'

@description('Tags applied to created resources.')
param tags object = {
  product: 'pounce-sentinel'
  environment: 'dev'
}

var normalizedPrefix = toLower(resourcePrefix)
var storageName = '${normalizedPrefix}st'
var appInsightsName = '${normalizedPrefix}-appi'
var planName = '${normalizedPrefix}-plan'
var functionName = '${normalizedPrefix}-api'
var cosmosName = '${normalizedPrefix}-cosmos'
var keyVaultName = '${normalizedPrefix}-kv'
var staticWebAppName = '${normalizedPrefix}-dashboard'
var keyVaultSecretsUserRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    Flow_Type: 'Bluefield'
    Request_Source: 'rest'
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = if (deployFunctionApp) {
  name: planName
  location: functionAppLocation
  tags: tags
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = if (deployFunctionApp) {
  name: functionName
  location: functionAppLocation
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storage.listKeys().keys[0].value}'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'POUNCE_SENTINEL_ENV'
          value: 'azure'
        }
        {
          name: 'POUNCE_SENTINEL_AUDIT_PATH'
          value: '/tmp/pounce-sentinel/verdicts.jsonl'
        }
        {
          name: 'AZURE_COSMOS_ACCOUNT_NAME'
          value: cosmos.name
        }
        {
          name: 'AZURE_COSMOS_DATABASE_NAME'
          value: database.name
        }
        {
          name: 'AZURE_COSMOS_VERDICTS_CONTAINER'
          value: verdicts.name
        }
        {
          name: 'AZURE_COSMOS_EXCEPTIONS_CONTAINER'
          value: exceptions.name
        }
        {
          name: 'AZURE_COSMOS_FEED_STATE_CONTAINER'
          value: feedState.name
        }
        {
          name: 'AZURE_COSMOS_CONNECTION_STRING'
          value: '@Microsoft.KeyVault(SecretUri=https://${keyVault.name}.vault.azure.net/secrets/pounce-cosmos-connection-string/)'
        }
        {
          name: 'POUNCE_IOC_FEED_URL'
          value: ''
        }
        {
          name: 'POUNCE_FEED_STALE_AFTER_HOURS'
          value: '1'
        }
        {
          name: 'POUNCE_FEED_FAILURE_MODE'
          value: 'warn'
        }
        {
          name: 'POUNCE_VULNERABILITY_ACTION'
          value: 'warn'
        }
        {
          name: 'POUNCE_ENABLE_LIVE_LOOKUPS'
          value: 'false'
        }
        {
          name: 'POUNCE_ENABLE_REGISTRY_PROVENANCE'
          value: 'false'
        }
        {
          name: 'SCM_DO_BUILD_DURING_DEPLOYMENT'
          value: 'true'
        }
        {
          name: 'ENABLE_ORYX_BUILD'
          value: 'true'
        }
        {
          name: 'PYTHON_ISOLATE_WORKER_DEPENDENCIES'
          value: '1'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
      ]
    }
  }
}

resource cosmos 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: cosmosName
  location: cosmosLocation
  tags: tags
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    enableAutomaticFailover: true
    minimalTlsVersion: 'Tls12'
    analyticalStorageConfiguration: {
      schemaType: 'WellDefined'
    }
    locations: [
      {
        locationName: cosmosLocation
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    capabilities: [
      {
        name: 'EnableServerless'
      }
    ]
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
  }
}

resource database 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmos
  name: 'pounce'
  properties: {
    resource: {
      id: 'pounce'
    }
  }
}

resource verdicts 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: database
  name: 'verdicts'
  properties: {
    resource: {
      id: 'verdicts'
      partitionKey: {
        paths: ['/repository']
        kind: 'Hash'
      }
      indexingPolicy: {
        automatic: true
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
      }
      conflictResolutionPolicy: {
        mode: 'LastWriterWins'
        conflictResolutionPath: '/_ts'
      }
    }
  }
}

resource exceptions 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: database
  name: 'exceptions'
  properties: {
    resource: {
      id: 'exceptions'
      partitionKey: {
        paths: ['/auditId']
        kind: 'Hash'
      }
      indexingPolicy: {
        automatic: true
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
      }
      conflictResolutionPolicy: {
        mode: 'LastWriterWins'
        conflictResolutionPath: '/_ts'
      }
    }
  }
}

resource feedState 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: database
  name: 'feed_state'
  properties: {
    resource: {
      id: 'feed_state'
      partitionKey: {
        paths: ['/kind']
        kind: 'Hash'
      }
      indexingPolicy: {
        automatic: true
        indexingMode: 'consistent'
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
      }
      conflictResolutionPolicy: {
        mode: 'LastWriterWins'
        conflictResolutionPath: '/_ts'
      }
    }
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    enableRbacAuthorization: true
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

resource functionAppKeyVaultSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployFunctionApp) {
  name: guid(keyVault.id, functionName, 'key-vault-secrets-user')
  scope: keyVault
  properties: {
    roleDefinitionId: keyVaultSecretsUserRoleDefinitionId
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource staticWebApp 'Microsoft.Web/staticSites@2023-12-01' = if (deployStaticWebApp) {
  name: staticWebAppName
  location: staticWebAppLocation
  tags: tags
  sku: {
    name: 'Free'
    tier: 'Free'
  }
  properties: {
    repositoryUrl: staticWebAppRepositoryUrl
    branch: staticWebAppBranch
    stagingEnvironmentPolicy: 'Enabled'
    allowConfigFileUpdates: true
  }
}

output functionAppName string = deployFunctionApp ? functionApp.name : ''
output functionAppUrl string = deployFunctionApp ? 'https://${functionName}.azurewebsites.net/api' : ''
output cosmosAccountName string = cosmos.name
output keyVaultName string = keyVault.name
output staticWebAppName string = deployStaticWebApp ? staticWebApp.name : ''
