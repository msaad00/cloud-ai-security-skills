targetScope = 'resourceGroup'

@description('Existing Azure Storage account that emits blob-created events.')
param sourceStorageAccountName string

@description('Source container name that receives raw objects.')
param sourceContainerName string

@description('Azure region for the runner resources.')
param location string = resourceGroup().location

@description('Service Bus namespace used by the runner.')
param serviceBusNamespaceName string

@description('Queue name that receives Event Grid blob-created messages.')
param ingestQueueName string = 'ingest-queue'

@description('Queue name that carries normalized event lines into detection.')
param detectQueueName string = 'detect-queue'

@description('Topic name for deduped findings fan-out.')
param alertsTopicName string = 'alerts-topic'

@description('Storage account used for replay-safe dedupe state.')
param dedupeStorageAccountName string

@description('Table name used for replay-safe dedupe state.')
param dedupeTableName string = 'runnerdedupe'

resource sourceStorage 'Microsoft.Storage/storageAccounts@2023-01-01' existing = {
  name: sourceStorageAccountName
}

resource dedupeStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: dedupeStorageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

resource serviceBusNamespace 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: serviceBusNamespaceName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
  properties: {
    minimumTlsVersion: '1.2'
  }
}

resource ingestQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: serviceBusNamespace
  name: ingestQueueName
  properties: {
    lockDuration: 'PT5M'
    maxDeliveryCount: 5
    requiresDuplicateDetection: false
    deadLetteringOnMessageExpiration: true
  }
}

resource detectQueue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: serviceBusNamespace
  name: detectQueueName
  properties: {
    lockDuration: 'PT5M'
    maxDeliveryCount: 5
    requiresDuplicateDetection: false
    deadLetteringOnMessageExpiration: true
  }
}

resource alertsTopic 'Microsoft.ServiceBus/namespaces/topics@2022-10-01-preview' = {
  parent: serviceBusNamespace
  name: alertsTopicName
  properties: {
    requiresDuplicateDetection: false
  }
}

resource sourceSystemTopic 'Microsoft.EventGrid/systemTopics@2022-06-15' = {
  name: '${sourceStorageAccountName}-blob-events'
  location: location
  properties: {
    source: sourceStorage.id
    topicType: 'Microsoft.Storage.StorageAccounts'
  }
}

resource blobCreatedToIngestQueue 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2022-06-15' = {
  parent: sourceSystemTopic
  name: 'blob-created-to-ingest-queue'
  properties: {
    eventDeliverySchema: 'EventGridSchema'
    filter: {
      includedEventTypes: [
        'Microsoft.Storage.BlobCreated'
      ]
      subjectBeginsWith: '/blobServices/default/containers/${sourceContainerName}/blobs/'
    }
    destination: {
      endpointType: 'ServiceBusQueue'
      properties: {
        resourceId: ingestQueue.id
      }
    }
  }
}

output sourceStorageAccountName string = sourceStorageAccountName
output sourceContainerName string = sourceContainerName
output serviceBusNamespaceFqdn string = serviceBusNamespace.properties.serviceBusEndpoint
output ingestQueueName string = ingestQueueName
output detectQueueName string = detectQueueName
output alertsTopicName string = alertsTopicName
output dedupeStorageAccountName string = dedupeStorageAccountName
output dedupeTableName string = dedupeTableName
output blobCreatedSubscriptionName string = blobCreatedToIngestQueue.name
