# Project README

## Overview

This project involves threat classification using machine learning models. It processes `.puml` files to extract features and predict potential threats.

## Requirements

Install the required packages using:

```bash
pip install -r requirements.txt
```

## Files

- `algorithm.ipynb`: Jupyter notebook for data preprocessing, model training, and evaluation.
- `app.py`: Streamlit application for uploading `.puml` files and predicting threats.
- `Streamlit.py`: Streamlit application for rendering and modifying PlantUML diagrams.
- `saved_steps.pkl`: Pickle file containing the trained model and preprocessing steps.

## Usage

### Running the Streamlit App

To run the Streamlit app, execute:

```bash
streamlit run app.py
```

### Uploading and Predicting

1. Upload a `.puml` file.
2. View the original and modified UML diagrams.
3. Click the 'Predict' button to classify the threat.

### Example 1

```python:app.py
64|def main():
65|    st.title('Threat Classification')
66|    
67|    uploaded_file = st.file_uploader("Choose a .puml file", type="puml")
68|    
69|    if uploaded_file is not None:
70|        puml_file_path = f"temp_{uploaded_file.name}"
71|        with open(puml_file_path, "wb") as f:
72|            f.write(uploaded_file.getbuffer())
73|        
74|        display_plantuml(puml_file_path)
75|        
76|        if st.button('Predict'):
77|            features_df = transform_puml_to_features(puml_file_path)
78|            expected_columns = data.best_estimator_.named_steps['preprocessor'].transformers_[1][2]
79|            for col in expected_columns:
80|                if col not in features_df.columns:
81|                    features_df[col] = 'Other'
82|            features_df = features_df[expected_columns]
83|            preprocessed_features = data.best_estimator_.named_steps['preprocessor'].transform(features_df)
84|            predictions = data.predict(preprocessed_features)
85|            prediction_labels = data.best_estimator_.named_steps['classifier'].classes_[predictions]
86|            st.write(f'The predicted threat is: {prediction_labels[0]}')
87|        
88|        os.remove(puml_file_path)
89|
90|if __name__ == "__main__":
91|    main()
```

## Model Training

The model is trained using a pipeline with preprocessing steps and a classifier. Hyperparameter tuning is performed using GridSearchCV.

### Example 2

```python:algorithm.ipynb
1044|    "grid_search.fit(X_train_res, y_train_res)\n",
1045|    "\n",
1046|    "# Predict on the test set\n",
1047|    "y_pred = grid_search.predict(X_test)\n",
1048|    "\n",
1049|    "# Decode the predictions back to original labels\n",
1050|    "y_test_decoded = label_encoder.inverse_transform(y_test)\n",
1051|    "y_pred_decoded = label_encoder.inverse_transform(y_pred)\n",
1052|    "\n",
1053|    "# Evaluate the model\n",
1054|    "print(\"Best parameters found: \", grid_search.best_params_)\n",
1055|    "print(\"Accuracy:\", accuracy_score(y_test_decoded, y_pred_decoded))\n",
1056|    "print(\"Classification Report:\\n\", classification_report(y_test_decoded, y_pred_decoded))"
```

## License

This project is licensed under the MIT License.
