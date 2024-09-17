import tkinter as tk
from tkinter import messagebox
import joblib
import pandas as pd
import numpy as np

model = joblib.load('model/one_class_svm_model.pkl')
scaler = joblib.load('scaler.pkl')
encoder = joblib.load('encoder.pkl')

columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
           'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
           'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
           'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
           'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
           'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
           'dst_host_srv_rerror_rate', 'label', 'score']

def predict_outcome():
    try:
        for i in range(len(columns)):
            input_data.append(entry[i].get())
                      
        input_data = np.array(input_data).reshape(1, -1)

        input_data_scaled = scaler.transform(input_data)

        prediction = model.predict(input_data_scaled)

        if prediction == 1:
            result = "Normal"
        else:
            result = "Anomalous"
        
        messagebox.showinfo("Prediction Result", f"The traffic is: {result}")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

window = tk.Tk()
window.title("Intrusion Detection Classifier")

entry = {}

for i in range(len(columns)):
    label = tk.Label(window, text=columns[i])
    label.pack()
    entry[i] = tk.Entry(window)
    entry[i].pack()

# Predict button
predict_button = tk.Button(window, text="Predict", command=predict_outcome)
predict_button.pack()

# Run the GUI
window.mainloop()










# Create an entry field for custom data
custom_data_label = tk.Label(root, text="Enter Review Text:", font=default_font)
custom_data_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')

custom_data_entry = tk.Text(root, height=10, width=50, font=default_font)
custom_data_entry.grid(row=1, column=0, padx=10, pady=5)

verified_purchase_var = tk.IntVar(value=1)  # Default is 1 (Verified)

# Create a Checkbutton to toggle Verified Purchase
verified_purchase_checkbutton = tk.Checkbutton(root, text="Verified Purchase", font=default_font, variable=verified_purchase_var)
verified_purchase_checkbutton.grid(row=2, column=0, padx=10, pady=5)

# Label to display prediction results
prediction_result_label = tk.Label(root, text="", font=default_font, fg="blue")
prediction_result_label.grid(row=4, column=0, padx=10, pady=10)

# Function to predict custom data
def predict_custom_data():
    try:
        # Get custom data from entry field
        text = custom_data_entry.get("1.0", tk.END).strip()
        verified_purchase = verified_purchase_var.get()

        df = pd.DataFrame({
            'REVIEW_TEXT': [text],
            'VERIFIED_PURCHASE': [verified_purchase],
        })
        df['Sentence_Embeddings'] = df['REVIEW_TEXT'].apply(lambda x: generate_word_embeddings(x, model))
        predictions = pipeline_model.predict(df)
        prediction = 'Fake' if predictions[0] == '__label1__' else 'Real'
        prediction_result_label.config(text=f"Prediction: {prediction}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create a button to predict custom data
custom_predict_button = tk.Button(root, text="Predict Review", font=default_font, command=predict_custom_data, bg="green", fg="white", width=20)
custom_predict_button.grid(row=3, column=0, padx=10, pady=10)

# Run the application
root.mainloop()
