import pandas as pd
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

files = [
    f for f in os.listdir(script_dir) 
    if (f.endswith(".csv") or f.startswith("kddcup")) 
    and f not in ["nodes.csv", "edges.csv", "kddcup.names", "typo-correction.txt"]
    and os.path.isfile(os.path.join(script_dir, f))
]

if not files:
    raise Exception(f"No dataset file found in: {script_dir}")

file_name = files[0]
file_path = os.path.join(script_dir, file_name)
print(f"Using dataset: {file_path}")

try:
    data = pd.read_csv(file_path, encoding='latin1')
except Exception as e:
    data = pd.read_csv(file_path, header=None, compression='infer')

sample = data.head(10)
columns = list(sample.columns)
name_idx = columns[0] if len(columns) > 0 else None
type_idx = columns[1] if len(columns) > 1 else None

nodes = []
for i, row in sample.iterrows():
    name = str(row[name_idx]) if name_idx is not None else f"Node_{i}"
    node_type = str(row[type_idx]) if type_idx is not None else "Unknown"

    nodes.append((
        i,
        name,
        node_type,
        "Medium",
        "Safe"
    ))

edges = []
for i in range(len(nodes) - 1):
    edges.append((i, i, i+1))

nodes_path = os.path.join(script_dir, "nodes.csv")
edges_path = os.path.join(script_dir, "edges.csv")

pd.DataFrame(nodes, columns=["id", "name", "type", "security_level", "status"]).to_csv(nodes_path, index=False)
pd.DataFrame(edges, columns=["id", "source", "target"]).to_csv(edges_path, index=False)

print(f"Successfully created nodes.csv and edges.csv in {script_dir}")