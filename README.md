# FastAPI Azure DevOps Alert Proxy

This project provides a FastAPI-based microservice that acts as a proxy for processing incoming alerts, checking if a corresponding Azure DevOps work item exists, and creating a new work item if one does not exist. It is designed to integrate with Azure DevOps and Kubernetes for seamless alert management.

## Features
- **Alert Webhook Handling**: Accepts JSON payloads from Alertmanager via a POST request to /alert.
- **Work Item Querying**: Checks if an existing work item with the same fingerprint exists in Azure DevOps.
- **Work Item Creation**: If no existing work item is found, a new "Bug" work item is created in Azure DevOps with the alert's details.
- **Logging**: Detailed logging for debugging and monitoring the state of incoming alerts and work item creation.

## Prerequisites
- **Azure DevOps**: You need an Azure DevOps account with the required permissions to create work items and query existing work items via the REST API.
- **Kubernetes**: This service is designed to run inside a Kubernetes cluster and assumes that it has access to a service account and associated secrets for authenticating with Azure DevOps.
- **Alertmanager**: Used to send alerts in the form of webhooks to this service.

## Setup

### Kubernetes Secret for Azure DevOps Token
1. Ensure that your Kubernetes cluster has a secret named azure-devops-token in the same namespace as this FastAPI application.
2. The secret should contain a key field named token with the value of your requested Azure DevOps personal access token (PAT).
3. Ensure the PAT token has the necessary permissions in order to list and create work items

### Deploying to Kubernetes
1. Build and deploy the FastAPI application container to your Kubernetes cluster.
2. Ensure the service account associated with the deployment has access to read the azure-devops-token secret within its own namespace.
3. Configure Alertmanager to send webhook alerts to the /alert endpoint of the FastAPI application.

## API Endpoint

### POST /alert
This endpoint accepts incoming alert notifications and processes them to create new work items in Azure DevOps if necessary.

#### Request Body

The request should be a JSON object containing the alerts array. Each alert should contain the following fields:
- labels.alertname: The name of the alert.
- fingerprint: A unique identifier for the alert (used to check if a work item with the same fingerprint already exists).

Example:
```json
{
  "alerts": [
     {
      "status": "firing",
      "labels": {
        "address": "DLQ",
        "alertname": "alert-name-test",
        "container": "alert-container-test",
        "namespace": "test-namespace",
        "pod": "test-pod",
        "severity": "warning"
      },
      "annotations": {
        "description": "describe this pod",
        "summary": "summary of this pod"
      },
      "startsAt": "2024-12-11T23:29:33.936Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "https://nohello.net",
      "fingerprint": "33f2ec9bd4827a1v"
    }
  ]
}
