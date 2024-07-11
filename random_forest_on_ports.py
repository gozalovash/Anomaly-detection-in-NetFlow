import pandas as pd
import matplotlib
matplotlib.use('TkAgg')
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt



# Load the labeled dataset
labeled_file_path = 'NF-UNSW-NB15-v2.csv'  # Update this path as needed
labeled_df = pd.read_csv(labeled_file_path)

# Load the unlabeled dataset
unlabeled_file_path = 'csvfile.csv'  # Update this path as needed
unlabeled_df = pd.read_csv(unlabeled_file_path)

# Display the first few rows of the labeled dataframe to understand its structure
print(labeled_df.head())
print(unlabeled_df.head())

# Focus on relevant columns: destination port, in bytes, out bytes, and label
labeled_df_relevant = labeled_df[['L4_DST_PORT', 'IN_BYTES', 'OUT_BYTES', 'Attack']]
unlabeled_df = unlabeled_df.rename(columns={'src_port': 'L4_DST_PORT', 'num_octets': 'SUM_BYTES'})
unlabeled_df_relevant = unlabeled_df[['L4_DST_PORT', 'SUM_BYTES']]  # Assuming 'SUM_BYTES' is the sum of IN_BYTES and OUT_BYTES
# Add a new column in labeled_df_relevant for the sum of IN_BYTES and OUT_BYTES
labeled_df_relevant['SUM_BYTES'] = labeled_df_relevant['IN_BYTES'] + labeled_df_relevant['OUT_BYTES']

# Classify labels into 'Benign' and 'Malicious'
labeled_df_relevant['Traffic_Type'] = labeled_df_relevant['Attack'].apply(lambda x: 'Benign' if x == 'Benign' else 'Malicious')

# Encode the Traffic_Type into numerical values: 'Benign' -> 0, 'Malicious' -> 1
labeled_df_relevant['Traffic_Type'] = labeled_df_relevant['Traffic_Type'].map({'Benign': 0, 'Malicious': 1})

# Separate features and target variable from labeled data
X = labeled_df_relevant[['L4_DST_PORT', 'SUM_BYTES']]
y = labeled_df_relevant['Traffic_Type']

# Split the labeled data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Standardize the features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Initialize the Random Forest Classifier
clf = RandomForestClassifier(random_state=42)

# Train the model
clf.fit(X_train, y_train)

# Evaluate the model on the test set
y_pred = clf.predict(X_test)
report = classification_report(y_test, y_pred)
print(report)

# Identify unique ports in the training set
unique_ports = set(X['L4_DST_PORT'])

# Process the unlabeled dataset
unlabeled_df_relevant['Prediction'] = None

for index, row in unlabeled_df_relevant.iterrows():
    if row['L4_DST_PORT'] in unique_ports:
        # Scale the row's features
        scaled_features = scaler.transform([[row['L4_DST_PORT'], row['SUM_BYTES']]])
        # Predict the traffic type
        prediction = clf.predict(scaled_features)
        unlabeled_df_relevant.at[index, 'Prediction'] = prediction[0]
    else:
        # Skip prediction for ports not seen during training
        unlabeled_df_relevant.at[index, 'Prediction'] = 'Unknown'

# Map predictions back to 'Benign' and 'Malicious'
unlabeled_df_relevant['Prediction'] = unlabeled_df_relevant['Prediction'].map({0: 'Benign', 1: 'Malicious', 'Unknown': 'Unknown'})

# Display the first few rows of the predictions
print(unlabeled_df_relevant.head())

# Save the predictions to a CSV file
output_file_path = 'app_predictions.csv'  # Update this path as needed
unlabeled_df_relevant.to_csv(output_file_path, index=False)
print(f"Predictions saved to {output_file_path}")

# Save the classification report to a text file
report_file_path = 'classification_report.txt'  # Update this path as needed
with open(report_file_path, 'w') as f:
    f.write(report)
print(f"Classification report saved to {report_file_path}")

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'Malicious'])
disp.plot(cmap=plt.cm.Blues)
plt.title('Confusion Matrix')
plt.grid(False)

confusion_matrix_path = 'confusion_matrix.png'
plt.savefig(confusion_matrix_path)
plt.close()

print(f"Confusion matrix saved to {confusion_matrix_path}")