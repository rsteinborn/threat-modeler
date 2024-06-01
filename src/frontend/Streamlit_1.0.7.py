import streamlit as st
import re
import pandas as pd
import pickle
from plantuml import PlantUML
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from fpdf import FPDF
from io import BytesIO
import base64
import requests


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
    containers = extract_containers(content)
    
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
    training_columns = [
        'SourceType', 'TargetType', 'AuthRequired', 'Encryption', 'EncryptionType', 
        'DataFormat', 'Frequency', 'DataIntegrity', 'AccessType', 'AccessTarget', 
        'NetworkProtocol', 'CommunicationChannel', 'CredentialStorage', 'Interactor'
    ]

    X_new = df[training_columns]

    X_new_encoded = encoder.transform(X_new)

    df_columns = encoder.get_feature_names_out()
    X_new_encoded_df = pd.DataFrame(X_new_encoded.toarray(), columns=df_columns)

    new_predictions = model.predict(X_new_encoded_df)

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
                new_relationship = f'Rel({source}, {target},"<color:red>{threat}")'
                return new_relationship
        return f'Rel({source}, {target}, "{threat}")'

    updated_content = pattern.sub(replace_threat, content)
    return updated_content

def get_recommendations(threats_df, recommendations_df):
    recommendations = []
    for threat in threats_df['Predicted_Threat'].unique():
        if threat in recommendations_df['Threat'].values:
            row = recommendations_df[recommendations_df['Threat'] == threat].iloc[0]
            recommendations.append({
                'Threat': threat,
                'Explanation': row['Explanation'],
                'Recommendation': row['Recommendation']
            })
    return recommendations

def generate_pdf(updated_diagram_url, recommendations):
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="DFD Analysis Report", ln=True, align='C')

    updated_image_response = requests.get(updated_diagram_url)
    updated_image_path = "updated_diagram.png"
    with open(updated_image_path, "wb") as file:
        file.write(updated_image_response.content)

    pdf.cell(200, 10, txt="Annotated DFD with Predicted Threats:", ln=True, align='L')
    pdf.image(updated_image_path, x=10, y=30, w=180)

    pdf.add_page()
    pdf.cell(200, 10, txt="Recommendations:", ln=True, align='L')
    for rec in recommendations:
        pdf.multi_cell(0, 10, txt=f"Threat: {rec['Threat']}\nRecommendation: {rec['Recommendation']}\nExplanation: {rec['Explanation']}\n", border=1)

    pdf_output = pdf.output(dest='S').encode('latin1')

    pdf_buffer = BytesIO(pdf_output)
    pdf_buffer.seek(0)

    return pdf_buffer

def colored_text(text, color):
    return f'<span style="color:{color};">{text}</span>'


def main():
    st.title("PlantUML DFD Analyzer")
    recommendations_path = "C:\\Users\\David\\Desktop\\Streamlit\\Recommendations.csv"
    recommendations_df = pd.read_csv(recommendations_path)

    if 'pdf_buffer' not in st.session_state:
        st.session_state.pdf_buffer = None

    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
    if uploaded_file is not None:
        file_content = uploaded_file.getvalue().decode("utf-8")
        
        col1, col2 = st.columns(2)
        with col1:
            display_plantuml(file_content, "Original DFD")

        df = parse_puml(file_content)
        
        if not df.empty:
            model, encoder = load_model('c:\\Users\\David\\Desktop\\Streamlit\\RF_algorithm_general.pkl')

            if st.button('Analyze DFD'):
                threats_df = analyze_dfd(model, encoder, df)

                updated_puml_content = add_threats_to_puml(file_content, threats_df)

                with col2:
                    display_plantuml(updated_puml_content, "Annotated DFD with Predicted Threats")

                recommendations = get_recommendations(threats_df, recommendations_df)

                st.write("Recommendations:")
                for rec in recommendations:
                    st.markdown(f'**<span style="color:red;">Threat:</span>** {colored_text(rec["Threat"], "red")}', unsafe_allow_html=True)
                    st.markdown(f'**Explanation:** {rec["Explanation"]}', unsafe_allow_html=True)
                    st.markdown(f'**Recommendation:** {rec["Recommendation"]}', unsafe_allow_html=True)
                    st.markdown("<hr>", unsafe_allow_html=True)

                updated_diagram_url = render_plantuml(updated_puml_content)
                pdf_buffer = generate_pdf(updated_diagram_url, recommendations)

                st.session_state.pdf_buffer = pdf_buffer

        else:
            st.warning("No relationships found in the uploaded PUML file.")

    if st.session_state.pdf_buffer is not None:
        st.download_button(
            label="Download PDF Report",
            data=st.session_state.pdf_buffer,
            file_name="DFD_Analysis_Report.pdf",
            mime="application/pdf"
        )

if __name__ == "__main__":
    main()





