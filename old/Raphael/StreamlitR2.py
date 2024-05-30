import streamlit as st
import os
from plantuml import PlantUML
from PIL import Image
import pickle
import pandas as pd

# Load the trained model
model_path = 'RF_algorithm.pkl'
with open(model_path, 'rb') as model_file:
    model = pickle.load(model_file)

def render_plantuml(puml_content):
    plantuml = PlantUML(url='http://www.plantuml.com/plantuml/img/')
    diagram_url = plantuml.get_url(puml_content)
    return diagram_url

def display_plantuml(puml_content, caption):
    diagram_url = render_plantuml(puml_content)
    if diagram_url:
        st.image(diagram_url, caption=caption)
    else:
        st.error("Failed to render PlantUML diagram")

def analyze_puml(puml_content, model):
    # Dummy analysis function for example purposes
    threats = ["Threat1", "Threat2", "Threat3"]
    # In a real scenario, you would use the model to predict threats
    new_puml_content = puml_content + "\n" + "\n".join([f"' {threat}" for threat in threats])
    return new_puml_content, threats

def save_and_process_file(uploaded_file):
    file_content = uploaded_file.getvalue().decode("utf-8")
    return file_content

st.title("Threat Modeling in PUML Files")

uploaded_file = st.file_uploader("Upload a PUML file", type="puml")

if uploaded_file is not None:
    original_puml_content = save_and_process_file(uploaded_file)
    st.subheader("Original Data Flow Diagram")
    display_plantuml(original_puml_content, "Original DFD")
    
    if st.button("Analyze"):
        new_puml_content, threats = analyze_puml(original_puml_content, model)
        
        st.subheader("Data Flow Diagram with Threats")
        display_plantuml(new_puml_content, "DFD with Threats")
        
        st.subheader("Identified Threats")
        threats_df = pd.DataFrame(threats, columns=["Threats"])
        st.table(threats_df)
