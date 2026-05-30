# Wazuh Security Visualization Dashboard

A lightweight dashboard built with Dash and Plotly for visualizing Wazuh alerts through a simple and centralized interface.

<img width="1900" height="847" alt="image" src="https://github.com/user-attachments/assets/b799c5e1-9c72-4352-8764-c384d73a7a6f" />


---

## About

Wazuh provides powerful visualization capabilities through the OpenSearch Dashboard, allowing users to create custom visualizations, dashboards, and investigations.

This project was created to provide a simpler dashboard experience focused on day-to-day monitoring and reporting.

Rather than building multiple visualizations in OpenSearch, this dashboard presents key security information in a single view, making it easier to monitor alerts, identify trends, and generate quick reports.

The objective is not to replace the OpenSearch Dashboard, but to offer an additional visualization layer that can be deployed quickly and used with minimal configuration.

---

## Features

### Security Overview

The dashboard provides an instant overview of:

* Total Alerts
* High Severity Alerts
* Active Agents
* Source IP Count

### Visualizations

The current version includes:

* Alert Timeline
* Top Triggered Rules
* Rule Severity Distribution
* Top Detected Source IPs

### Filtering

Alerts can be filtered using:

* Time Range
* Agent
* Rule Level
* Rule ID
* Smart Search

### Reporting

Generate a consolidated security report containing all available visualizations in a single export.

Included charts:

* Alert Timeline
* Top Detected IPs
* Top Triggered Rules
* Severity Distribution

### Automatic Refresh

The dashboard automatically refreshes to display updated alert information.

---

## Smart Search

The Smart Search field allows quick filtering without manually selecting dashboard filters.

Examples:

```text
rule 5710
```

```text
level 10
```

```text
agent 001
```

```text
authentication failure
```

```text
ssh login
```

---

## Current Status

### Available

* Alert visualization
* Alert analytics
* Rule analytics
* Source IP analytics
* Security reporting
* Dashboard filtering

### Under Development

Inventory-related visualizations are currently being developed and are not yet fully supported.

Planned additions include:

* Installed package analytics
* Process visualization
* Operating system analytics
* CPU information
* Memory information
* Asset inventory dashboards

---

## Requirements

Python 3.10 or later.

Install dependencies:

```bash
pip install -r requirements.txt
```

Example dependencies:

```text
dash
pandas
plotly
requests
flask
kaleido
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Stuti3097/wazuh-security-visualization-dashboard.git

cd wazuh-security-visualization-dashboard
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a file named:

```text
config.ini
```

Example:

```ini
[indexer]
username=your_username
password=your_password
alerts_index=https://YOUR_INDEXER_IP:9200/wazuh-alerts-*/_search
inventory_index=https://YOUR_INDEXER_IP:9200/wazuh-states-inventory-*/_search
```

Update the values according to your environment:

* Replace `YOUR_INDEXER_IP` with the IP address or hostname of your Wazuh Indexer.
* Replace `your_username` with your Indexer username.
* Replace `your_password` with your Indexer password.

---

## Running the Dashboard

Start the application:

```bash
python3 app.py
```

Once running, open your browser and access:

```text
http://YOUR_SERVER_IP:7200
```

Example:

```text
http://192.168.1.100:7200
```

Replace `YOUR_SERVER_IP` with the IP address of the machine where the dashboard is running.

---

## Repository Structure

```text
wazuh-security-dashboard/
│
├── app.py
├── requirements.txt
├── config.ini.example
├── README.md
│
└── screenshots/
   └── dashboard.png


```

---

## Notes

* The dashboard retrieves data directly from the Wazuh Indexer API.
* Ensure connectivity between the dashboard host and the Wazuh Indexer.
* If your environment uses SSL certificates, adjust the connection settings accordingly.
* Inventory visualization features are still under development and may change in future releases.

---

## Contributing

Contributions are welcome.

Feel free to open issues for bugs, feature requests, or dashboard improvements. Pull requests are also appreciated.

---

## Disclaimer

This is an independent community project and is not an official Wazuh product.

Use and test the project according to your organization's requirements before deploying it in production environments.

