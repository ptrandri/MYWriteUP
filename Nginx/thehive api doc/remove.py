import requests

# Replace with your own TheHive instance URL and API key

thehive_url = ''
api_key = ''


# List of alert IDs you want to delete
alert_ids = range(1, 1001)  # Replace with the range of alert IDs you want to delete

# Loop to delete each alert
for alert_id in alert_ids:
    # Send a DELETE request to TheHive's API
    url = f"{thehive_url}/alert/~{alert_id}"
    headers = {
        'Authorization': f'Bearer {api_key}'
    }

    response = requests.delete(url, headers=headers)

    if response.status_code == 200:
        print(f"Deleted alert {alert_id}")
    else:
        print(f"Failed to delete alert {alert_id}: {response.status_code} - {response.text}")
