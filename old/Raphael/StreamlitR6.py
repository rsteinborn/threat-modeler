import streamlit as st
import re
import pandas as pd
import pickle
from plantuml import PlantUML
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer

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
    entity_pattern = re.compile(r'(Person|System|Container|ContainerDb|System_Ext)\(([^,]+),\s*"([^"]+)",\s*"([^"]+)"(?:,\s*"([^"]*)")?\)')
    entities.extend(entity_pattern.findall(file_content))

    # Extracting relationships
    relationship_pattern = re.compile(r'Rel\(([^,]+),\s*([^,]+),\s*"([^"]+)"(?:,\s*"([^"]*)")?\)')
    relationships.extend(relationship_pattern.findall(file_content))

    # Debug: Print extracted entities and relationships
    st.write("Extracted Entities:", entities)
    st.write("Extracted Relationships:", relationships)

    return entities, relationships

def process_entities(entities):
    entity_dict = {}
    for entity in entities:
        entity_type, alias, name, description = entity[:4]
        entity_dict[alias] = {
            'SourceType': entity_type,
            'SourceDescription': description,
            'SourceName': name
        }
    # Debug: Print processed entities
    st.write("Processed Entities Dictionary:", entity_dict)
    return entity_dict

def process_relationships(relationships, entity_dict):
    relationship_data = []
    for rel in relationships:
        source, destination, label, details = rel[:4]
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
            'SourceDescription': entity_dict[source]['SourceDescription'] if source in entity_dict else None,
            'TargetName': entity_dict[destination]['SourceName'] if destination in entity_dict else None,
            'TargetType': entity_dict[destination]['SourceType'] if destination in entity_dict else None,
            'TargetDescription': entity_dict[destination]['SourceDescription'] if destination in entity_dict else None,
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
    # Debug: Print processed relationships
    st.write("Processed Relationships Data:", relationship_data)
    return relationship_data

def load_model(pickle_file):
    with open(pickle_file, 'rb') as file:
        model, encoder = pickle.load(file)
    return model, encoder

def analyze_dfd(model, encoder, df):
    # Define the columns that were used during model training
    training_columns = [
        'SourceType', 'TargetType', 'AuthRequired', 'Encryption', 'EncryptionType', 
        'DataFormat', 'Frequency', 'DataIntegrity', 'AccessType', 'AccessTarget', 
        'NetworkProtocol', 'CommunicationChannel', 'CredentialStorage', 'Interactor'
    ]

    # Ensure the DataFrame only contains the columns used during training
    df_filtered = df[training_columns]

    # Impute missing values with 'Missing'
    imputer = SimpleImputer(strategy='constant', fill_value='Missing')
    df_imputed = imputer.fit_transform(df_filtered)
    df_imputed = pd.DataFrame(df_imputed, columns=df_filtered.columns)

    # Print the order of columns in df_imputed
    st.write("Order of columns in df_imputed:")
    st.write(df_imputed.columns.tolist())

    # Transform the data using the loaded encoder
    X_encoded = encoder.transform(df_imputed)
    X_encoded_df = pd.DataFrame(X_encoded.toarray(), columns=encoder.get_feature_names_out(df_imputed.columns))

    # Use the loaded model to predict threats
    threats = model.predict(X_encoded_df)

    # Add the threats to the DataFrame
    df['Threat'] = threats

    return df

def modify_puml(file_content, threats):
    modified_content = file_content
    for threat in threats:
        if threat["Threat"] and threat["Threat"] != 'None':
            # Find the relationship line and replace it with the threat and red arrow
            pattern = re.compile(rf'Rel\(([^,]+),\s*{threat["TargetName"]},\s*"[^"]*"\)')
            modified_content = pattern.sub(rf'Rel(\1, {threat["TargetName"]}, "{threat["Threat"]}", $lineColor="red")', modified_content)
    
    # Print the modified PUML content to the console
    print(modified_content)
    
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

        df = pd.DataFrame(relationship_data)
        st.write("Extracted Relationships DataFrame:", df)

        model_file = st.file_uploader("Choose a model .pkl file", type="pkl")
        if model_file is not None:
            model, encoder = load_model(model_file)
            
            if st.button("Analyze DFD"):
                analyzed_df = analyze_dfd(model, encoder, df)
                st.write("Analyzed DFD with Threats:", analyzed_df)

                modified_puml_content = modify_puml(file_content, analyzed_df.to_dict(orient='records'))
                with col2:
                    display_plantuml(modified_puml_content, "Modified DFD with Threats")

if __name__ == "__main__":
    main()