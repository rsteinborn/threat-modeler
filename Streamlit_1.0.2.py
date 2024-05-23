import streamlit as st
import re
import pandas as pd
import pickle
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
            'SourceType': entity_type,
            'SourceDescription': description
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
            'SourceType': entity_dict[source]['SourceType'] if source in entity_dict else None,
            'TargetType': entity_dict[destination]['SourceType'] if destination in entity_dict else None,
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

def load_model(pickle_file):
    with open(pickle_file, 'rb') as file:
        model = pickle.load(file)
    return model

def analyze_dfd(model, preprocessor, df):
    # Transform the data using the preprocessor
    df_transformed = preprocessor.transform(df)
    
    # Assuming the model returns a list of threats for each relationship
    threats = model.predict(df_transformed)
    
    # Create a list of dictionaries to store the threats with their corresponding target names
    threat_list = []
    for i, threat in enumerate(threats):
        threat_list.append({
            "TargetName": df.iloc[i]["TargetName"],
            "Threat": threat
        })
    
    return threat_list

def modify_puml(file_content, threats):
    modified_content = file_content
    for threat in threats:
        if "TargetName" in threat and "Threat" in threat and threat["Threat"]:
            # Find the relationship line and replace it with the threat and red arrow
            pattern = re.compile(rf'Rel\(([^,]+),\s*{threat["TargetName"]},\s*"[^"]*"\)')
            modified_content = pattern.sub(rf'Rel(\1, {threat["TargetName"]}, "{threat["Threat"]}", $lineColor="red")', modified_content)
    return modified_content

def main():
    st.title("PlantUML DFD Analyzer")

    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue().decode("utf-8")
        
        col1, col2 = st.columns(2)
        with col1:
            display_plantuml(file_content, "Original DFD")

        entities, relationships = parse_puml_file(file_content)
        entity_dict = process_entities(entities)
        relationship_data = process_relationships(relationships, entity_dict)
        
        if relationship_data:
            df = pd.DataFrame(relationship_data)
            st.write("Extracted Relationships DataFrame:")
            st.dataframe(df)

            model = load_model('saved_steps.pkl')
            best_estimator = model.best_estimator_
            preprocessor = best_estimator.named_steps['preprocessor']

            # Ensure the test data has the same columns as the training data
            df = df[preprocessor.feature_names_in_]

            # Remove the 'Threat' column from the features
            if 'Threat' in df.columns:
                df = df.drop(columns=['Threat'])

            if st.button('Analyze DFD'):
                threats = analyze_dfd(best_estimator, preprocessor, df)
                
                # Füge die Bedrohungen in die 'Threat'-Spalte ein
                df['Threat'] = [threat["Threat"] for threat in threats]
                
                # Modifizieren der PUML-Datei, um die erkannten Bedrohungen einzuzeichnen
                modified_content = modify_puml(file_content, threats)
                
                with col2:
                    display_plantuml(modified_content, "Modified DFD with Threats")
                
                # Erstelle eine Tabelle mit allen erkannten Bedrohungen
                threat_table = pd.DataFrame([{'Threat': threat['Threat'], 'TargetName': threat['TargetName']} for threat in threats])
                st.write("Identified Threats:")
                st.dataframe(threat_table)
        else:
            st.warning("No relationships found in the uploaded PUML file.")

if __name__ == "__main__":
    main()
