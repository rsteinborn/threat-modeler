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

def parse_puml(file_path):
    content = file_path
    containers = extract_containers(content)
    pattern = re.compile(
        r'Rel\((\w+)\s*,\s*(\w+)\s*,\s*"(.*?)"\s*,\s*"(.*?)"\)',
        re.DOTALL
    )
    matches = pattern.findall(content)
    data = []
    for match in matches:
        source, target, relationship, details = match
        details_dict = {
            'SourceType': containers.get(source),
            'TargetType': containers.get(target),
            'Relationship': relationship,
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
        }
        data.append(details_dict)
    
    df = pd.DataFrame(data)
    return df

def load_model(pickle_file):
    with open(pickle_file, 'rb') as file:
        model, encoder = pickle.load(file)
    return model, encoder

def analyze_dfd(model, encoder, fileContent):
    # Load and parse the PUML file
    df = fileContent
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

def modify_puml(file_content, threats):
    # Ensure the necessary C4-PlantUML library references are included
    include_statements = """
    @startuml
    !include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Container.puml
    !include https://raw.githubusercontent.com/plantuml-stdlib/C4-PlantUML/master/C4_Context.puml
    """

    # Check if the include statements are already present
    if "!include" not in file_content:
        modified_content = include_statements + file_content
    else:
        modified_content = file_content

    for index, threat in threats.iterrows():
        if threat["Predicted_Threat"] and threat["Predicted_Threat"] != 'None':
            pattern = re.compile(rf'Rel\(([^,]+),\s*([^,]+),\s*"{re.escape(threat["Relationship"])}"\s*,\s*"(.*?)"\)')
            modified_content = pattern.sub(rf'Rel(\1, \2, "{threat["Relationship"]}", "{threat["Predicted_Threat"]}", $lineColor="red")', modified_content)
    
    return modified_content

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

            model, encoder = load_model('RF_algorithm_general.pkl')

            if st.button('Analyze DFD'):
                threats_df = analyze_dfd(model, encoder, df)
                st.write("Analyzed DFD with Threats:")
                st.dataframe(threats_df)

                # Modify the PUML content to include the predicted threats
                modified_puml_content = modify_puml(file_content, threats_df)
                with col2:
                    display_plantuml(modified_puml_content, "Modified DFD with Threats")

        else:
            st.warning("No relationships found in the uploaded PUML file.")

if __name__ == "__main__":
    main()