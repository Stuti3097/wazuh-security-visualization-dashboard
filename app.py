import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.io as pio
import plotly.graph_objects as go
import requests
from flask import Flask
import base64
import re

import configparser

config = configparser.ConfigParser()
config.read("config.ini")
ALERTS_INDEX = config["indexer"]["alerts_index"]
INVENTORY_INDEX = config["indexer"]["inventory_index"]
INDEXER_USER = config["indexer"]["username"]
INDEXER_PASS = config["indexer"]["password"]
server = Flask(__name__)
app = dash.Dash(__name__, server=server)

app.index_string = """
<!DOCTYPE html>
<html>
<head>
{%metas%}
<title>Wazuh Dashboard</title>
{%favicon%}
{%css%}

<style>

body{
background:radial-gradient(circle at top,#1a2333,#05080f);
color:white;
font-family:Arial;
}

.card{
padding:20px;
border-radius:12px;
width:220px;
color:white;
}

.card-blue{background:#1f3c72;}
.card-red{background:#c31432;}
.card-green{background:#11998e;}
.card-orange{background:#f7971e;}

.filter-bar{
background:#111827;
padding:20px;
border-radius:12px;
display:flex;
gap:15px;
align-items:end;
margin-bottom:20px;
}

.panel{
background:#111827;
padding:20px;
border-radius:12px;
margin-bottom:20px;
}

.js-plotly-plot .plotly .modebar{
top:-30px !important;
right:10px !important;
}

</style>
</head>

<body>
{%app_entry%}
<footer>
{%config%}
{%scripts%}
{%renderer%}
</footer>
</body>
</html>
"""

def get_alerts(query_range):

    query = {
        "size": 1000,
        "query": {
            "range": {
                "@timestamp": query_range
            }
        }
    }

    r = requests.get(
        ALERTS_INDEX,
        json=query,
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False
    )
    hits = r.json()["hits"]["hits"]

    alerts = []

    for h in hits:
        src = h["_source"]

        alerts.append({
            "rule_id": src["rule"]["id"],
            "rule_description": src["rule"]["description"],
            "rule_level": src["rule"]["level"],
            "agent": src["agent"]["id"],
            "agent_name": src["agent"]["name"],
            "srcip": src.get("data", {}).get("srcip", "unknown"),
            "timestamp": src["@timestamp"]
        })

    return pd.DataFrame(alerts)

def get_inventory():

    query = {
        "size": 5000,
        "query": {"match_all": {}}
    }

    r = requests.get(
        INVENTORY_INDEX,
        json=query,
        auth=(INDEXER_USER, INDEXER_PASS),
        verify=False
    )

    hits = r.json()["hits"]["hits"]

    rows=[]

    for h in hits:
        src=h["_source"]

        rows.append({
            "agent":src.get("agent",{}).get("name"),
            "os":src.get("host",{}).get("os",{}).get("name"),
            "process":src.get("process",{}).get("name"),
            "package":src.get("package",{}).get("name"),
            "cpu":src.get("host",{}).get("cpu",{}).get("name"),
            "memory":src.get("host",{}).get("memory",{}).get("total")
        })

    return pd.DataFrame(rows)


app.layout = html.Div([

html.H2("Wazuh Security Visualization Dashboard"),

html.Div([
html.Div(id="card-total",className="card card-blue"),
html.Div(id="card-high",className="card card-red"),
html.Div(id="card-agents",className="card card-green"),
html.Div(id="card-ip",className="card card-orange")
],style={"display":"flex","gap":"20px","marginBottom":"20px"}),

html.Div([

html.Div([
html.Label("Time Range"),

dcc.Dropdown(
id="time-filter",
options=[
{"label":"Last 15 minutes","value":"now-15m"},
{"label":"Last 1 hour","value":"now-1h"},
{"label":"Last 6 hours","value":"now-6h"},
{"label":"Last 24 hours","value":"now-24h"},
{"label":"Last 7 days","value":"now-7d"},
{"label":"Custom Range","value":"custom"}
],
value="now-24h",
clearable=False,
style={"backgroundColor":"white","color":"black"}
),

html.Div(
dcc.DatePickerRange(
id="custom-range",
display_format="YYYY-MM-DD",
style={"backgroundColor":"white","color":"black"}
),
id="calendar-container",
style={"display":"none","marginTop":"6px","backgroundColor":"white","color":"black"}
)

],style={"width":"250px"}),

html.Div([
html.Label("Agent"),
dcc.Dropdown(id="agent-filter",multi=True,style={"backgroundColor":"white","color":"black"})
],style={"width":"200px"}),

html.Div([
html.Label("Rule Level"),
dcc.Dropdown(id="rulelevel-filter",multi=True,style={"backgroundColor":"white","color":"black"})
],style={"width":"150px"}),

html.Div([
html.Label("Rule ID"),
dcc.Dropdown(id="ruleid-filter",multi=True,style={"backgroundColor":"white","color":"black"})
],style={"width":"150px"}),

html.Div([
html.Label("DQL Search"),
dcc.Input(id="dql-search",placeholder="rule_id:5710 rule_level:10",style={"backgroundColor":"white","color":"black"})
],style={"width":"250px"}),

html.Div([
html.Label("Smart Search"),
dcc.Input(
id="smart_search",
placeholder="Example: show rule 554 or login failures",
style={"backgroundColor":"white","color":"black"}
)
],style={"width":"260px"}),

html.Button("Refresh",id="refresh-btn"),

html.Button(
"Download Report",
id="download-btn",
style={
"backgroundColor":"#2563eb",
"color":"white",
"padding":"8px 14px",
"border":"none",
"borderRadius":"6px"
}
),

dcc.Download(id="download")

],className="filter-bar"),

html.Div([
html.Div([
html.H4("Alert Timeline"),
dcc.Graph(id="timeline-chart")
],className="panel",style={"width":"60%"}),

html.Div([
html.H4("Detecting IPs"),
dcc.Graph(id="ip-chart")
],className="panel",style={"width":"40%"})
],style={"display":"flex","gap":"20px"}),

html.Div([
html.Div([
html.H4("Top Triggered Rules"),
dcc.Graph(id="rules-chart")
],className="panel",style={"width":"50%"}),

html.Div([
html.H4("Rule Level Distribution"),
dcc.Graph(id="rulelevel-chart")
],className="panel",style={"width":"50%"})
],style={"display":"flex","gap":"20px"}),

dcc.Interval(id="interval",interval=10000)

])

@app.callback(
Output("calendar-container","style"),
Input("time-filter","value")
)
def toggle_calendar(value):

    if value == "custom":
        return {"display":"block","marginTop":"6px"}
    else:
        return {"display":"none"}

@app.callback(

Output("card-total","children"),
Output("card-high","children"),
Output("card-agents","children"),
Output("card-ip","children"),

Output("timeline-chart","figure"),
Output("ip-chart","figure"),
Output("rules-chart","figure"),
Output("rulelevel-chart","figure"),

Output("agent-filter","options"),
Output("rulelevel-filter","options"),
Output("ruleid-filter","options"),

Input("interval","n_intervals"),
Input("refresh-btn","n_clicks"),
Input("time-filter","value"),
Input("custom-range","start_date"),
Input("custom-range","end_date"),
Input("agent-filter","value"),
Input("rulelevel-filter","value"),
Input("ruleid-filter","value"),
Input("dql-search","value"),
Input("smart_search","value")

)

def update_dashboard(_,refresh,time_filter,start_date,end_date,agent,rulelevel,ruleid,dql,smart_search):

    if time_filter=="custom" and start_date and end_date:

        query_range={
        "gte":start_date,
        "lte":end_date
        }

    else:

        query_range={
        "gte":time_filter
        }

    # ---------------- AI DATA SOURCE SWITCH ----------------

    prompt = smart_search.lower() if smart_search else ""

    inventory_keywords=[
    "process",
    "package",
    "software",
    "os",
    "operating system",
    "cpu",
    "memory"
    ]

    if any(k in prompt for k in inventory_keywords):
        df=get_inventory()
    else:
        df=get_alerts(query_range)

    # -------------------------------------------------------

    if smart_search:
        prompt = smart_search.lower()

        rule_match = re.search(r"rule\s*(\d+)", prompt)
        level_match = re.search(r"level\s*(\d+)", prompt)
        agent_match = re.search(r"agent\s*(\d+)", prompt)

        if rule_match:
             ruleid=[rule_match.group(1)]

        if level_match:
             rulelevel=[int(level_match.group(1))]

        if agent_match:
             agent=[agent_match.group(1)]

        if not rule_match and not level_match and not agent_match:
            if "rule_description" in df.columns:
                df = df[df["rule_description"].str.lower().str.contains(prompt, na=False)]

# --------------------------------------------------

    if df.empty:

        empty=go.Figure()

        return(
        html.Div(["Total Alerts",html.H2(0)]),
        html.Div(["High Rule Level Alerts",html.H2(0)]),
        html.Div(["Active Agents",html.H2(0)]),
        html.Div(["Source IPs",html.H2(0)]),
        empty,empty,empty,empty,[],[],[]
        )

    if agent:
        df=df[df["agent"].isin(agent)]

    if rulelevel:
        df=df[df["rule_level"].isin(rulelevel)]

    if ruleid:
        df=df[df["rule_id"].isin(ruleid)]

    total=len(df)
    high=len(df[df["rule_level"]>=7])
    agents=df["agent"].nunique()
    ips=df["srcip"].nunique()

    df["time"]=pd.to_datetime(df["timestamp"])

    timeline=df.groupby(df["time"].dt.floor("5min")).size().reset_index(name="alerts")
    fig_timeline=px.line(timeline,x="time",y="alerts")

    ip_counts=df.groupby("srcip").size().reset_index(name="count")
    fig_ip=px.bar(ip_counts,x="count",y="srcip",orientation="h",color="count",color_continuous_scale="Turbo")

    rule_counts=df.groupby("rule_description").size().reset_index(name="count")
    fig_rules=px.bar(rule_counts,x="count",y="rule_description",orientation="h",color="count",color_continuous_scale="Turbo")

    sev_counts=df.groupby("rule_level").size().reset_index(name="count")
    fig_sev=px.bar(sev_counts,x="rule_level",y="count",color="count",color_continuous_scale="Turbo")

    for f in [fig_timeline,fig_ip,fig_rules,fig_sev]:
        f.update_layout(template="plotly_dark")

    return(
    html.Div(["Total Alerts",html.H2(total)]),
    html.Div(["High Rule Level Alerts",html.H2(high)]),
    html.Div(["Active Agents",html.H2(agents)]),
    html.Div(["Source IPs",html.H2(ips)]),
    fig_timeline,
    fig_ip,
    fig_rules,
    fig_sev,
    [{"label":i,"value":i} for i in df["agent"].unique()],
    [{"label":i,"value":i} for i in sorted(df["rule_level"].unique())],
    [{"label":i,"value":i} for i in sorted(df["rule_id"].unique())]
    )

# -------------------------
# DOWNLOAD REPORT
# -------------------------

@app.callback(
    Output("download","data"),
    Input("download-btn","n_clicks"),
    State("timeline-chart","figure"),
    State("rules-chart","figure"),
    State("rulelevel-chart","figure"),
    State("ip-chart","figure"),
    State("time-filter","value"),
    prevent_initial_call=True
)
def download_dashboard(n_clicks,f1,f2,f3,f4,time_range):

    import plotly.io as pio
    import plotly.graph_objects as go
    import base64

    # convert dash dict → plotly figure
    f1 = go.Figure(f1)
    f2 = go.Figure(f2)
    f3 = go.Figure(f3)
    f4 = go.Figure(f4)


    # add titles
    f1["layout"]["title"]={"text":"Alert Timeline","x":0.5}
    f2["layout"]["title"]={"text":"Top Detected IPs","x":0.5}
    f3["layout"]["title"]={"text":"Top Triggered Rules","x":0.5}
    f4["layout"]["title"]={"text":"Severity Distribution","x":0.5}

    for f in [f1,f2,f3,f4]:
        f["layout"]["width"]=1400
        f["layout"]["height"]=450
        f["layout"]["margin"]=dict(l=200,r=50,t=80,b=80)

    img1 = base64.b64encode(pio.to_image(f1,format="png",scale=1)).decode()
    img2 = base64.b64encode(pio.to_image(f2,format="png",scale=1)).decode()
    img3 = base64.b64encode(pio.to_image(f3,format="png",scale=1)).decode()
    img4 = base64.b64encode(pio.to_image(f4,format="png",scale=1)).decode()

    report = go.Figure()

    report.add_layout_image(dict(
        source="data:image/png;base64,"+img1,
        x=0.5,y=1,sizex=1,sizey=0.24,
        xanchor="center",xref="paper",yref="paper"
    ))

    report.add_layout_image(dict(
        source="data:image/png;base64,"+img2,
        x=0.5,y=0.75,sizex=1,sizey=0.24,
        xanchor="center",xref="paper",yref="paper"
    ))

    report.add_layout_image(dict(
        source="data:image/png;base64,"+img3,
        x=0.5,y=0.50,sizex=1,sizey=0.24,
        xanchor="center",xref="paper",yref="paper"
    ))

    report.add_layout_image(dict(
        source="data:image/png;base64,"+img4,
        x=0.5,y=0.25,sizex=1,sizey=0.24,
        xanchor="center",xref="paper",yref="paper"
    ))

    report.update_layout(
        template="plotly_dark",
        height=1900,
        width=1500,
        title={"text":f"Wazuh Security Report | Time: {time_range}","x":0.5},
        xaxis=dict(visible=False),
        yaxis=dict(visible=False)
    )

    # Faster: avoid second kaleido render
    img = pio.to_image(report,format="png",engine="kaleido",scale=1)

    return dcc.send_bytes(
        lambda buffer: buffer.write(img),
        "wazuh_security_report.png"
    )


if __name__=="__main__":
    app.run(host="0.0.0.0",port=7200)

