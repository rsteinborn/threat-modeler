import streamlit as st
import os
from plantuml import PlantUML
from PIL import Image

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

def save_and_process_file(uploaded_file):
    file_content = uploaded_file.getvalue().decode("utf-8")
    lines = file_content.split('\n')
    modified_lines = []
    for line in lines:
        if "@startuml" in line:
            modified_lines.append(line)
            modified_lines.append("Alice -> Bob: Neue Nachricht")
        else:
            modified_lines.append(line)
    
    modified_content = "\n".join(modified_lines)
    
    return file_content, modified_content  # Rückgabe des Original- und des geänderten Inhalts

def main():
    st.title("PlantUML Viewer")
    
    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    
    if uploaded_file is not None:
        original_content, modified_content = save_and_process_file(uploaded_file)
        
        # Anzeigen der UML-Diagramme nebeneinander
        col1, col2 = st.columns(2)
        with col1:
            display_plantuml(original_content, "Original Version")
        with col2:
            display_plantuml(modified_content, "Modified Version")

if __name__ == "__main__":
    main()