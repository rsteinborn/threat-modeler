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

def extract_containers(content):
    container_pattern = re.compile(
        r'(Container|ContainerDb|System_Ext|Person)\((\w+), "(.*?)", "(.*?)", "(.*?)\\nSourceType: (.*?)"\)',
        re.DOTALL
    )
    containers = {}
    matches = container_pattern.findall(content)
    for match in matches:
        container_type, var_name, name, description, _, source_type = match
        containers[var_name.strip()] = source_type.strip()
    return containers

def parse_puml(content):
    # Extract containers to map their types
    containers = extract_containers(content)
    
    # Adjusted regex pattern to capture all relevant fields
    pattern = re.compile(
        r'Rel\((\w+)\s*,\s*(\w+)\s*,\s*"(.*?)"\s*,\s*"(.*?)"\)',
        re.DOTALL
    )
    
    matches = pattern.findall(content)
    data = []
    for match in matches:
        source, target, relationship, details = match
        source, target = source.strip(), target.strip()
        
        details_dict = {
            'Source': source,
            'Target': target,
            'SourceType': containers.get(source),
            'TargetType': containers.get(target),
            'AuthRequired': re.search(r'AuthRequired:\s*(.*?)(,|$)', details).group(1) if re.search(r'AuthRequired:\s*(.*?)(,|$)', details) else None,
            'Encryption': re.search(r'Encryption:\s*(.*?)(,|$)', details).group(1) if re.search(r'Encryption:\s*(.*?)(,|$)', details) else None,
            'EncryptionType': re.search(r'EncryptionType:\s*(.*?)(,|$)', details).group(1) if re.search(r'EncryptionType:\s*(.*?)(,|$)', details) else None,
            'DataFormat': re.search(r'DataFormat:\s*(.*?)(,|$)', details).group(1) if re.search(r'DataFormat:\s*(.*?)(,|$)', details) else None,
            'Frequency': re.search(r'Frequency:\s*(.*?)(,|$)', details).group(1) if re.search(r'Frequency:\s*(.*?)(,|$)', details) else None,
            'DataIntegrity': re.search(r'DataIntegrity:\s*(.*?)(,|$)', details).group(1) if re.search(r'DataIntegrity:\s*(.*?)(,|$)', details) else None,
            'AccessType': re.search(r'AccessType:\s*(.*?)(,|$)', details).group(1) if re.search(r'AccessType:\s*(.*?)(,|$)', details) else None,
            'AccessTarget': re.search(r'AccessTarget:\s*(.*?)(,|$)', details).group(1) if re.search(r'AccessTarget:\s*(.*?)(,|$)', details) else None,
            'NetworkProtocol': re.search(r'NetworkProtocol:\s*(.*?)(,|$)', details).group(1) if re.search(r'NetworkProtocol:\s*(.*?)(,|$)', details) else None,
            'CommunicationChannel': re.search(r'CommunicationChannel:\s*(.*?)(,|$)', details).group(1) if re.search(r'CommunicationChannel:\s*(.*?)(,|$)', details) else None,
            'CredentialStorage': re.search(r'CredentialStorage:\s*(.*?)(,|$)', details).group(1) if re.search(r'CredentialStorage:\s*(.*?)(,|$)', details) else None,
            'Interactor': re.search(r'Interactor:\s*(.*?)(,|$)', details).group(1) if re.search(r'Interactor:\s*(.*?)(,|$)', details) else None,
            'Threat': re.search(r'Threat:\s*(.*?)(,|$)', details).group(1) if re.search(r'Threat:\s*(.*?)(,|$)', details) else None,
        }
        
        data.append(details_dict)
    
    df = pd.DataFrame(data)
    return df

def load_model(pickle_file):
    with open(pickle_file, 'rb') as file:
        model, encoder = pickle.load(file)
    return model, encoder

def analyze_dfd(model, encoder, df):
    # List of columns used during training (excluding 'Threat')
    training_columns = [
        'SourceType', 'TargetType', 'AuthRequired', 'Encryption', 'EncryptionType', 
        'DataFormat', 'Frequency', 'DataIntegrity', 'AccessType', 'AccessTarget', 
        'NetworkProtocol', 'CommunicationChannel', 'CredentialStorage', 'Interactor'
    ]

    # Ensure columns are in the same order as during training and exclude unwanted columns
    X_new = df[training_columns]

    # Preprocess the data using the loaded encoder
    X_new_encoded = encoder.transform(X_new)

    # Convert to DataFrame to align feature names
    df_columns = encoder.get_feature_names_out()
    X_new_encoded_df = pd.DataFrame(X_new_encoded.toarray(), columns=df_columns)

    # Make predictions
    new_predictions = model.predict(X_new_encoded_df)

    # Add the predictions to the new data
    df['Predicted_Threat'] = new_predictions

    return df

def add_threats_to_puml(content, threats_df):
    pattern = re.compile(
        r'(Rel\((\w+),\s*(\w+),\s*"(.*?)",\s*"(.*?)"\))',
        re.DOTALL
    )

    def replace_threat(match):
        rel, source, target, relationship, details = match.groups()
        source, target = source.strip(), target.strip()
        threat_row = threats_df[(threats_df['Source'] == source) & (threats_df['Target'] == target)]
        if not threat_row.empty:
            threat = threat_row['Predicted_Threat'].values[0]
            if threat and threat != "No Threat":
                # If a threat exists, show only source, target, and threat in red
                new_relationship = f'Rel({source}, {target},"<color:red>{threat}")'
                return new_relationship
        # If no threat or threat is "No Threat", keep the original relationship details in black
        return f'Rel({source}, {target}, "{threat}")'

    updated_content = pattern.sub(replace_threat, content)
    return updated_content


def main():
    st.title("PlantUML DFD Analyzer")

    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue().decode("utf-8")
        
        col1, col2 = st.columns(2)
        with col1:
            display_plantuml(file_content, "Original DFD")

        # Use the new parse_puml method
        df = parse_puml(file_content)
        
        if not df.empty:
            st.write("Extracted Relationships DataFrame:")
            st.dataframe(df)

            model, encoder = load_model('saved_models/RF_algorithm_1.0.4.pkl')

            if st.button('Analyze DFD'):
                threats_df = analyze_dfd(model, encoder, df)

                # Add the predicted threats to the PUML content
                updated_puml_content = add_threats_to_puml(file_content, threats_df)

                # Display the updated DFD with predicted threats
                with col2:
                    display_plantuml(updated_puml_content, "Annotated DFD with Predicted Threats")

                st.write("Annotated Relationships DataFrame:")
                st.dataframe(threats_df)
        else:
            st.warning("No relationships found in the uploaded PUML file.")

if __name__ == "__main__":
    main()
