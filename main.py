import pandas as pd
import os

base_path = os.path.dirname(__file__)

nodes = pd.read_csv(os.path.join(base_path, "nodes.csv"))
edges = pd.read_csv(os.path.join(base_path, "edges.csv"))

print("Nodes Loaded:")
print(nodes.head())

print("\nEdges Loaded:")
print(edges.head())

def convert_to_jsonld(nodes, edges):
    json_ld = {"@context": "https://schema.org", "@graph": []}

    for _, node in nodes.iterrows():
        connections = edges[edges["source"] == node["id"]]["target"].tolist()

        json_ld["@graph"].append({
            "@type": "NetworkNode",
            "id": str(node["id"]),
            "name": node["name"],
            "nodeType": node["type"],
            "securityLevel": node["security_level"],
            "connectedTo": [str(c) for c in connections]
        })

    return json_ld


json_data = convert_to_jsonld(nodes, edges)

print("\nJSON-LD Representation:")
print(json_data)