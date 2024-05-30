import streamlit as st
import os
from plantuml import PlantUML
import pickle
import pandas as pd
from sklearn.preprocessing import LabelEncoder

def load_model():
    with open('saved_steps.pkl', 'rb') as file:
        data = pickle.load(file)
    return data

data = load_model()

def render_plantuml(puml_file):
    plantuml = PlantUML(url='http://www.plantuml.com/plantuml/img/')
    with open(puml_file, 'r') as file:
        puml_content = file.read()
    diagram_url = plantuml.get_url(puml_content)
    return diagram_url

def display_plantuml(puml_file):
    diagram_url = render_plantuml(puml_file)
    if diagram_url:
        st.image(diagram_url)
    else:
        st.error("Failed to render PlantUML diagram")

def transform_puml_to_features(puml_file_path):
    with open(puml_file_path, 'r') as file:
        puml_content = file.read()
        
    # Mock parsing logic - Replace with actual parsing
    features = {
        'SourceType': [],
        'TargetType': [],
        'Relationship': [],
        'AuthRequired': [],
        'Encryption': [],
        'EncryptionType': [],
        'DataFormat': [],
        'Frequency': [],
        'DataIntegrity': [],
        'AccessType': [],
        'AccessTarget': [],
        'NetworkProtocol': [],
        'CommunicationChannel': [],
        'CredentialStorage': [],
        'Interactor': []
    }
    
    if 'Database' in puml_content:
        features['SourceType'].append('Database')
    else:
        features['SourceType'].append('Other')

    # Assuming mock values for the other features for demonstration
    for key in features.keys():
        if key != 'SourceType':
            features[key].append('Other')

    return pd.DataFrame(features)

def main():
    st.title('Threat Classification')
    
    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    
    if uploaded_file is not None:
        puml_file_path = f"temp_{uploaded_file.name}"
        with open(puml_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        display_plantuml(puml_file_path)
        
        if st.button('Predict'):
            # Transform the .puml file to feature DataFrame
            features_df = transform_puml_to_features(puml_file_path)
            
            # Ensure all necessary columns are present and ordered
            expected_columns = data.best_estimator_.named_steps['preprocessor'].transformers_[1][2]  # Assuming the second transformer is for categorical features
            for col in expected_columns:
                if col not in features_df.columns:
                    features_df[col] = 'Other'  # Add missing columns with a default value
            features_df = features_df[expected_columns]  # Reorder columns to match training data
            
            # Preprocess the features
            preprocessed_features = data.best_estimator_.named_steps['preprocessor'].transform(features_df)
            
            # Make predictions
            predictions = data.predict(preprocessed_features)
            prediction_labels = data.best_estimator_.named_steps['classifier'].classes_[predictions]
            
            st.write(f'The predicted threat is: {prediction_labels[0]}')
        
        os.remove(puml_file_path)  # Clean up the temporary file

if __name__ == "__main__":
    main()
