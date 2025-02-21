from fastapi import FastAPI, Request, HTTPException
from kubernetes import client, config
import logging
import json
import requests
import base64

# Initialize FastAPI app
app = FastAPI()

# Set up logging
logging.basicConfig(level=logging.INFO)

# Suppress specific logging from Kubernetes client for sensitive secret data
logging.getLogger("kubernetes").setLevel(logging.WARNING)

# Get the current namespace from the service account file
namespace_file = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
try:
    with open(namespace_file, "r") as f:
        namespace = f.read().strip()
except FileNotFoundError as e:
    logging.error(f"Namespace file not found: {e}")
    raise HTTPException(status_code=500, detail="Namespace file not found")
except Exception as e:
    logging.error(f"Error reading namespace file: {e}")
    raise HTTPException(status_code=500, detail="Error reading namespace file")

# Load Kubernetes configuration and retrieve Azure DevOps token
try:
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret("azure-devops-pat-token", namespace)

    if not secret.data:
        logging.error("Secret data is empty")
        raise HTTPException(status_code=500, detail="Azure DevOps token missing in secret")

    decoded_data = {key: base64.b64decode(value).decode("utf-8") for key, value in secret.data.items()}
    token_value = decoded_data.get("token")

    if not token_value:
        logging.error("Token key missing in secret data")
        raise HTTPException(status_code=500, detail="Azure DevOps token not found")
except Exception as e:
    logging.error(f"Error loading Kubernetes configuration or secret: {e}")
    raise HTTPException(status_code=500, detail="Error loading Kubernetes configuration or secret")

# Azure DevOps API URLs
azure_devops_url = "https://dev.azure.com/{organization}/{project}/_apis/wit/workitems/$Bug?api-version=7.2-preview.3"
azure_devops_url_query = "https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.2-preview.2"


@app.post("/alert")
async def alert_proxy(request: Request) -> dict:
# Handles incoming alerts and creates work items in Azure DevOps if necessary. 
    try:
        alert_data = await request.json()
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        logging.error(f"Error reading alert data: {e}")
        raise HTTPException(status_code=500, detail="Error reading alert data")

    # Generate authentication headers inside the function
    auth_value = base64.b64encode(f":{token_value}".encode("utf-8")).decode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {auth_value}",
    }

    response_messages = []  # Collect response messages

    for alert in alert_data.get("alerts", []):
        system_info = json.dumps(alert)
        alert_name = alert.get("labels", {}).get("alertname", "Unknown Alert")
        fingerprint = alert.get("fingerprint", "unknown")

        if fingerprint == "unknown":
            logging.warning(f"Skipping alert due to missing fingerprint: {alert}")
            response_messages.append("Skipping alert due to missing fingerprint")
            continue

        # Query Azure DevOps to check if work item already exists
        wiql_query = {
            "query": f"SELECT [System.Id] FROM WorkItems WHERE [System.WorkItemType] = 'Bug' AND [System.Tags] CONTAINS '{fingerprint}'"
        }

        try:
            response = requests.post(azure_devops_url_query, headers=headers, json=wiql_query)
            response.raise_for_status()
            query_result = response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying work items: {e}")
            return {"status": "failure", "message": f"Error querying work items: {str(e)}"}

        # If no existing bug, create a new work item
        if not query_result.get("workItems", []):
            logging.info(f"No existing bug with fingerprint {fingerprint} found. Creating a new work item.")

            payload = [
                {"op": "add", "path": "/fields/System.Title", "value": alert_name},
                {"op": "add", "path": "/fields/Microsoft.VSTS.TCM.SystemInfo", "value": system_info},
                {"op": "add", "path": "/fields/System.Tags", "value": fingerprint},
            ]

            headers["Content-Type"] = "application/json-patch+json"  # Change content type for POST request

            try:
                post_response = requests.post(azure_devops_url, headers=headers, json=payload)
                post_response.raise_for_status()
            except requests.exceptions.RequestException as e:
                logging.error(f"Error creating work item: {e}")
                return {"status": "failure", "message": f"Error creating work item: {str(e)}"}

            if post_response.status_code in [200, 201]:
                logging.info(f"Successfully created work item for {alert_name} ({fingerprint})")
                response_messages.append(f"Work item created for alert {alert_name}")
            else:
                response_messages.append(f"Failed to create work item for alert {alert_name}: {post_response.text}")
        else:
            logging.info(f"Existing bug with fingerprint {fingerprint} found. Skipping creation.")
            response_messages.append(f"Bug with fingerprint {fingerprint} already exists. Skipping creation.")

    return {"status": "success", "messages": response_messages}
