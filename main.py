from fastapi import FastAPI, Request, HTTPException
from kubernetes import client, config
import logging
import json
import requests
import base64

app = FastAPI()

# Set up logging
logging.basicConfig(level=logging.INFO)

#Suppress specific logging from kubernetes client for sensitive secret data
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

# Load the kubeconfig to interact with the cluster and read + pass in the secret value for the azure token
try:
    config.load_incluster_config()
    v1 = client.CoreV1Api()

    secret = v1.read_namespaced_secret("azure-devops-pat-token", namespace)
    secret_data = secret.data
    decoded_data = {key: base64.b64decode(value).decode('utf-8') for key, value in secret_data.items()}

    token_value = decoded_data.get('token')
    if not token_value:
        raise KeyError("Token not found in the secret")
except Exception as e:
    logging.error(f"Error loading Kubernetes configuration or secret: {e}")
    raise HTTPException(status_code=500, detail="Error loading Kubernetes configuration or secret")

auth_value = base64.b64encode(f":{token_value}".encode('utf-8')).decode('utf-8')

azure_devops_url = "https://dev.azure.com/{organization}/{project}_apis/wit/workitems/$Bug?api-version=7.2-preview.3"
azure_devops_url_query = "https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.2-preview.2"

query_headers = {
    'Content-Type': 'application/json',
    'Authorization': f"Basic {auth_value}",
}

post_headers = {
    'Content-Type': 'application/json-patch+json',
    'Authorization': f"Basic {auth_value}",
}

@app.post("/alert")
async def alert_proxy(request: Request):
    # Step 1: Capture the incoming Alertmanager webhook
    try:
        alert_data = await request.json()
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    except Exception as e:
        logging.error(f"Error reading alert data: {e}")
        raise HTTPException(status_code=500, detail="Error reading alert data")

    # Step 2: Loop through all alerts and process each one
    response_messages = []  # List to hold the messages for each alert

    for alert in alert_data.get('alerts', []):
        try:
            system_info = json.dumps(alert)
            alert_name = alert['labels']['alertname']
            fingerprint = alert['fingerprint']
        except KeyError as e:
            logging.warning(f"Missing expected key in alert data: {e}")
            response_messages.append(f"Skipping alert due to missing key: {e}")
            continue  # Skip this alert if the key is missing

        # Check if a Bug work item with the given fingerprint tag already exists
        wiql_query = {
            "query": f"SELECT [System.Id] FROM WorkItems WHERE [System.WorkItemType] = 'Bug' AND [System.Tags] CONTAINS '{fingerprint}'"
        }

        # Send the WIQL query to Azure DevOps to find existing work items with the fingerprint
        try:
            response = requests.post(azure_devops_url_query, headers=query_headers, data=json.dumps(wiql_query))
            response.raise_for_status()  # Will raise an exception for status codes >= 400
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying work items: {e}")
            return {"status": "failure", "message": f"Error querying work items: {str(e)}"}

        if response.status_code == 200:
            result = response.json()

            logging.debug("Query response: \n %s", result)

            # If the workItems array is empty, it means no bug with the fingerprint exists. Proceed with creation.
            if not result.get('workItems', []):
                logging.info(f"No existing bug with fingerprint {fingerprint} found. Proceeding to create a new work item.")

                # Prepare the payload for Azure DevOps Work Item creation
                payload = json.dumps([
                    {
                        "op": "add",
                        "path": "/fields/System.Title",
                        "value": alert_name
                    },
                    {
                        "op": "add",
                        "path": "/fields/Microsoft.VSTS.TCM.SystemInfo",
                        "value": system_info
                    },
                    {
                        "op": "add",
                        "path": "/fields/System.Tags",
                        "value": fingerprint
                    }
                ])

                # Send the POST request to create a work item
                try:
                    post_response = requests.post(azure_devops_url, headers=post_headers, data=payload)
                    post_response.raise_for_status()  # Will raise an exception for status codes >= 400
                except requests.exceptions.RequestException as e:
                    logging.error(f"Error creating work item: {e}")
                    return {"status": "failure", "message": f"Error creating work item: {str(e)}"}

                logging.debug(f"Work item creation response: {post_response.status_code}, {post_response.text}")

                if post_response.status_code in [200, 201]:
                    response_messages.append(f"Work item created for alert {alert_name} with fingerprint {fingerprint}")
                else:
                    response_messages.append(f"Failed to create work item for alert {alert_name} with fingerprint {fingerprint}. Error: {post_response.text}")
            else:
                logging.info(f"Existing bug with fingerprint {fingerprint} found. Skipping creation.")
                response_messages.append(f"Bug with fingerprint {fingerprint} already exists. Skipping creation.")
        else:
            logging.error(f"Error querying work items: {response.status_code} - {response.text}")
            response_messages.append(f"Error querying work items for fingerprint {fingerprint}: {response.text}")

    # Return the collected messages for all alerts
    return {"status": "success", "messages": response_messages}