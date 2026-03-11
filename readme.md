# CyberTwin – Cyber Attack Simulation Platform

CyberTwin is a conceptual cybersecurity simulation platform designed to help organizations visualize and prepare for cyber attacks on critical infrastructure before they occur.

Instead of reacting to cyber incidents after damage has begun, CyberTwin aims to enable proactive risk assessment through digital twin modeling and attack simulations.

The platform models interconnected infrastructure systems such as hospitals, public databases, communication networks, and public services as a dynamic digital network. Administrators can simulate cyber attack scenarios, observe how threats propagate through systems, and evaluate defensive strategies to strengthen resilience.

---

## Problem

Modern cities rely heavily on interconnected digital systems to operate essential services such as healthcare, transportation, emergency response systems, and public databases.

While this connectivity improves efficiency, it also makes infrastructure increasingly vulnerable to cyber attacks. Threats like ransomware, phishing breaches, and unauthorized access can spread rapidly across connected systems.

Most cybersecurity solutions today are reactive and detect attacks only after damage has already started. Unlike physical disasters such as floods or earthquakes, which cities regularly simulate to prepare for emergencies, there are very few tools that allow authorities to simulate cyber disasters in advance.

This lack of proactive preparedness makes it difficult for institutions to understand vulnerabilities and respond effectively to large-scale cyber threats.

---

## Solution

CyberTwin introduces the concept of a **digital twin for cybersecurity infrastructure**.

The platform creates a simulated model of interconnected systems and allows administrators to run cyber attack simulations to understand how threats might spread across infrastructure networks.

Using machine learning–based anomaly detection and network simulation, CyberTwin helps users:

- Simulate cyber attacks such as ransomware or phishing breaches
- Visualize how threats propagate across connected systems
- Identify vulnerable infrastructure nodes
- Test defensive strategies before real incidents occur

This shifts cybersecurity from reactive incident response to proactive risk prevention.

---

## Key Features

### Cyber Attack Simulation Engine
Simulates real-world cyber attacks including ransomware outbreaks, phishing compromises, and network intrusions to demonstrate how threats propagate across infrastructure.

### Digital Twin Infrastructure Modeling
Creates a visual digital model of critical systems such as hospitals, databases, and service networks to represent system dependencies and vulnerabilities.

### AI-Powered Threat Prediction
Uses machine learning models to detect abnormal activity and predict possible attack paths in infrastructure networks.

### Real-Time Attack Visualization
Provides an interactive dashboard that visually maps attack propagation across networks.

### Proactive Cyber Defense
Allows administrators to test defensive strategies such as isolating compromised systems or strengthening security controls.

---

## Planned Architecture

The system will consist of four major components:

1. **Simulation Engine**
2. **Machine Learning Threat Detection**
3. **Visualization Dashboard**
4. **Infrastructure Data Management**

These components work together to simulate attack scenarios and provide insights for cybersecurity preparedness.

---

## Technology Stack

### Core Simulation Engine
- Python 3.10+
- NetworkX for graph-based infrastructure modeling
- SimPy for discrete-event cyber attack simulation

### Machine Learning & Predictive Analytics
- Scikit-learn for anomaly detection
- Pandas and NumPy for telemetry and log analysis
- MITRE ATT&CK Framework for realistic threat modeling

### Visualization Dashboard
- Streamlit for interactive web dashboards
- PyVis / Graphviz for network visualization
- Plotly for threat analytics and heatmaps

### Infrastructure & Data Management
- SQLite for simulation data storage
- JSON-LD for structured infrastructure data representation

---

## Example Use Case

A city administrator wants to understand how a ransomware attack on a hospital system might impact other connected services.

Using CyberTwin they can:

1. Load the digital twin of the infrastructure network
2. Simulate a ransomware attack on a hospital node
3. Visualize how the attack spreads across connected systems
4. Test defense strategies such as isolating affected nodes
5. Identify vulnerable infrastructure components

---

## Project Status

🚧 This project is currently in the **concept and planning stage**.

Future development will include:

- Cyber attack propagation simulation engine
- Interactive digital twin visualization
- Machine learning based anomaly detection
- Security risk analysis dashboard

---

## Team

**Team Name:** Aaram over Kaam

Members:

- Saara — ADGIPS (GGSIPU)
- Aman Raj — Jaypee Institute of Information Technology
- Prabgun Mokha — ADGIPS (GGSIPU)
- Puru Gupta — JIMS (GGSIPU)

---

## References

Government Frameworks

- National Cyber Security Policy – Ministry of Electronics & IT
- Indian Computer Emergency Response Team (CERT-In)
- National Critical Information Infrastructure Protection Centre (NCIIPC)

Research Frameworks

- NIST Cybersecurity Framework
- ENISA Critical Infrastructure Cyber Resilience

Datasets

- UNSW-NB15 Cyber Attack Dataset

---
