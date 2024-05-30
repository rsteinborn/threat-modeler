import streamlit as st
import re
import pandas as pd
from plantuml import PlantUML

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

def parse_puml_file(file_content):
    entities = []
    relationships = []

    # Extracting entities
    entity_pattern = re.compile(r'(Person|System|Container|ContainerDb)\(([^,]+),\s*"([^"]+)",\s*"([^"]+)"\)')
    entities.extend(entity_pattern.findall(file_content))

    # Extracting relationships
    relationship_pattern = re.compile(r'Rel\(([^,]+),\s*([^,]+),\s*"([^"]+)"(?:,\s*"((?!Threat:).+?)")?\)')
    relationships.extend(relationship_pattern.findall(file_content))

    return entities, relationships

def process_entities(entities):
    entity_dict = {}
    for entity in entities:
        entity_type, alias, name, description = entity
        entity_dict[alias] = {
            'Type': entity_type,
            'Name': name,
            'Description': description
        }
    return entity_dict

def process_relationships(relationships, entity_dict):
    relationship_data = []
    for rel in relationships:
        source, destination, label, details = rel
        details_dict = {}

        if details:
            detail_parts = details.split(', ')
            for part in detail_parts:
                key_value = part.split(': ')
                if len(key_value) == 2:
                    key, value = key_value
                    details_dict[key] = value

        relationship_data.append({
            'SourceType': entity_dict[source]['Type'] if source in entity_dict else None,
            'SourceDescription': entity_dict[source]['Description'] if source in entity_dict else None,
            'TargetName': destination,
            'TargetType': entity_dict[destination]['Type'] if destination in entity_dict else None,
            'TargetDescription': entity_dict[destination]['Description'] if destination in entity_dict else None,
            'Relationship': label,
            'AuthRequired': details_dict.get('AuthRequired', ''),
            'Encryption': details_dict.get('Encryption', ''),
            'EncryptionType': details_dict.get('EncryptionType', ''),
            'DataFormat': details_dict.get('DataFormat', ''),
            'Frequency': details_dict.get('Frequency', ''),
            'DataIntegrity': details_dict.get('DataIntegrity', ''),
            'AccessType': details_dict.get('AccessType', ''),
            'AccessTarget': details_dict.get('AccessTarget', ''),
            'NetworkProtocol': details_dict.get('NetworkProtocol', ''),
            'CommunicationChannel': details_dict.get('CommunicationChannel', ''),
            'CredentialStorage': details_dict.get('CredentialStorage', ''),
            'Interactor': details_dict.get('Interactor', '')
        })
    return relationship_data

def main():
    st.title("PlantUML Viewer")
    
    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue().decode("utf-8")
        
        # Anzeigen der UML-Diagramme
        col1, col2 = st.columns(2)
        with col1:
            display_plantuml(file_content, "Original Version")
        
        # Extrahieren und Anzeigen der Beziehungen in einem DataFrame
        entities, relationships = parse_puml_file(file_content)
        entity_dict = process_entities(entities)
        relationship_data = process_relationships(relationships, entity_dict)
        
        if relationship_data:
            df = pd.DataFrame(relationship_data)
            st.write("Extracted Relationships DataFrame:")
            st.dataframe(df)  # Anzeige der Tabelle in Streamlit
        else:
            st.warning("No relationships found in the uploaded PUML file.")

if __name__ == "__main__":
    main()