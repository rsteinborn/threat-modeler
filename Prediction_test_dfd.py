import pickle
import pandas as pd
import re
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import RandomForestClassifier

# Load the model and encoder from the pickle file
with open('RF_algorithm_general.pkl', 'rb') as file:
    rf_classifier, onehot_encoder_features = pickle.load(file)

# # Load the model and encoder from the pickle file
# with open('RF_algorithm_1.0.1.pkl', 'rb') as file:
#     rf_classifier, onehot_encoder_features = pickle.load(file)

# # Load the model and encoder from the pickle file
# with open('RF_algorithm_1.0.2.pkl', 'rb') as file:
#     rf_classifier, onehot_encoder_features = pickle.load(file)

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
    with open(file_path, 'r') as file:
        content = file.read()
    
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

# Load and parse the PUML file
df = parse_puml('testpuml2.puml')

# List of columns used during training (excluding 'Threat')
training_columns = [
    'SourceType', 'TargetType', 'AuthRequired', 'Encryption', 'EncryptionType', 
    'DataFormat', 'Frequency', 'DataIntegrity', 'AccessType', 'AccessTarget', 
    'NetworkProtocol', 'CommunicationChannel', 'CredentialStorage', 'Interactor'
]

# Ensure columns are in the same order as during training and exclude unwanted columns
X_new = df[training_columns]

# Preprocess the data using the loaded encoder
X_new_encoded = onehot_encoder_features.transform(X_new)

# Convert to DataFrame to align feature names
df_columns = onehot_encoder_features.get_feature_names_out()
X_new_encoded_df = pd.DataFrame(X_new_encoded.toarray(), columns=df_columns)

# Make predictions
new_predictions = rf_classifier.predict(X_new_encoded_df)

# Add the predictions to the new data
df['Predicted_Threat'] = new_predictions

# Save the updated data to a new Excel file
#df.to_excel('new_data_with_predictions.xlsx', index=False)

# If true labels are available in the new data, calculate and display metrics
if 'Threat' in df.columns:
    y_true = df['Threat']
    y_pred = new_predictions
    
    # Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    report = classification_report(y_true, y_pred)
    
    print("\nAccuracy on new data:", accuracy)
    print("\nClassification Report on new data:\n", report)

# After making predictions and adding the predictions to the new data
df['Predicted_Threat'] = new_predictions

# Save the updated data to a new Excel file
df.to_excel('new_data_with_predictions.xlsx', index=False)

# Print the DataFrame to see the true labels and the predicted labels for each row
print(df[['Threat', 'Predicted_Threat']])
