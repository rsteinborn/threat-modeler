import streamlit as st
import re
import pandas as pd
from plantuml import PlantUML
import pickle
import os

# Load the model
def load_model():
    with open('saved_steps.pkl', 'rb') as file:
        data = pickle.load(file)
    return data

model_data = load_model()

# Function to render PlantUML content and return the diagram URL
def render_plantuml(puml_content):
    plantuml = PlantUML(url='http://www.plantuml.com/plantuml/img/')
    diagram_url = plantuml.get_url(puml_content)
    return diagram_url

# Function to display the PlantUML diagram in Streamlit
def display_plantuml(puml_content, caption):
    diagram_url = render_plantuml(puml_content)
    if diagram_url:
        st.image(diagram_url, caption=caption)
    else:
        st.error("Failed to render PlantUML diagram")

# Function to parse the content of a .puml file and extract entities and relationships
def parse_puml_file(file_content):
    entities = []
    relationships = []

    # Extracting entities using regex
    entity_pattern = re.compile(r'(Person|System|Container|ContainerDb)\(([^,]+),\s*"([^"]+)",\s*"([^"]+)"\)')
    entities.extend(entity_pattern.findall(file_content))

    # Extracting relationships using regex
    relationship_pattern = re.compile(r'Rel\(([^,]+),\s*([^,]+),\s*"([^"]+)"(?:,\s*"((?!Threat:).+?)")?\)')
    relationships.extend(relationship_pattern.findall(file_content))

    return entities, relationships

# Function to process extracted entities into a dictionary
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

# Function to process extracted relationships and enrich them with entity details
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

# Function to generate a new .puml file with predicted threats
def generate_puml_with_threats(relationships, predictions):
    new_puml_content = "@startuml\n"
    for rel, threat in zip(relationships, predictions):
        source, destination, label, details = rel
        new_puml_content += f'Rel({source}, {destination}, "{label}", "{details}, Threat: {threat}")\n'
    new_puml_content += "@enduml"
    return new_puml_content

# Main function to run the Streamlit app
def main():
    st.title("PlantUML Viewer")
    
    # File uploader for .puml files
    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue().decode("utf-8")
        
        # Display the original UML diagram
        col1, col2 = st.columns(2)
        with col1:
            display_plantuml(file_content, "Original Version")
        
        # Extract and display relationships in a DataFrame
        entities, relationships = parse_puml_file(file_content)
        entity_dict = process_entities(entities)
        relationship_data = process_relationships(relationships, entity_dict)
        
        if relationship_data:
            df = pd.DataFrame(relationship_data)
            st.write("Extracted Relationships DataFrame:")
            st.dataframe(df)  # Display the DataFrame in Streamlit
            
            if st.button('Predict'):
                # Preprocess the features
                features_df = pd.DataFrame(relationship_data)
                expected_columns = model_data.best_estimator_.named_steps['preprocessor'].transformers_[1][2]
                for col in expected_columns:
                    if col not in features_df.columns:
                        features_df[col] = 'Other'
                features_df = features_df[expected_columns]
                preprocessed_features = model_data.best_estimator_.named_steps['preprocessor'].transform(features_df)
                
                # Make predictions
                predictions = model_data.predict(preprocessed_features)
                prediction_labels = model_data.best_estimator_.named_steps['classifier'].classes_[predictions]
                
                # Generate new .puml file with predicted threats
                new_puml_content = generate_puml_with_threats(relationships, prediction_labels)
                new_puml_path = "predicted_threats.puml"
                with open(new_puml_path, "w") as f:
                    f.write(new_puml_content)
                
                # Display the new UML diagram
                with col2:
                    display_plantuml(new_puml_content, "Predicted Threats Version")
                
                # Display the list of predicted threats
                st.write("Predicted Threats:")
                st.write(prediction_labels)
                
                # Clean up the temporary file
                os.remove(new_puml_path)
        else:
            st.warning("No relationships found in the uploaded PUML file.")

# Entry point of the script
if __name__ == "__main__":
    main()
