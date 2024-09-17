import tkinter as tk
from tkinter import messagebox
import joblib
import pandas as pd
import numpy as np
from tkinter import ttk

model = joblib.load('model/one_class_svm_model.pkl')
scaler = joblib.load('model/scaler.pkl')
encoder_service = joblib.load('model/encoder_service.pkl')
encoder_flag = joblib.load('model/encoder_flag.pkl')
encoder_protocol = joblib.load('model/encoder_protocol_type.pkl')


columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
           'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
           'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'is_host_login',
           'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
           'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
           'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
           'dst_host_srv_rerror_rate']

categorical_features = {'protocol_type': ['tcp', 'udp', 'icmp'],
                        'service': ['private','ftp_data','eco_i','telnet','http','smtp','ftp',
                                 'ldap','pop_3','courier','discard','ecr_i','imap4','domain_u',
                                 'mtp','systat','iso_tsap','other','csnet_ns','finger','uucp',
                                 'whois','netbios_ns','link','Z39_50','sunrpc','auth','netbios_dgm',
                                 'uucp_path','vmnet','domain','name','pop_2','http_443','urp_i','login',
                                 'gopher','exec','time','remote_job','ssh','kshell','sql_net','shell',
                                 'hostnames','echo','daytime','pm_dump','IRC','netstat','ctf','nntp',
                                 'netbios_ssn','tim_i','supdup','bgp','nnsp','rje','printer','efs','X11',
                                 'ntp_u','klogin','tftp_u'],
                        'flag': ['REJ', 'SF', 'RSTO', 'S0', 'RSTR', 'SH', 'S3', 'S2', 'S1', 'RSTOS0', 'OTH']}
binary_features = ['land', 'logged_in', 'root_shell', 'su_attempted', 'is_host_login', 'is_guest_login']
numerical_features = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
                      'num_compromised', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'count', 
                      'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
                      'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                      'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                      'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
                      'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']


# Function to process the input when a button is clicked
def process_input():
    # Get values from dropdowns
    selected_protocol = protocol_type_var.get()
    selected_service = service_var.get()
    selected_flag = flag_var.get()
    
    # Get values from entry fields
    numerical_values = {feature: numerical_vars[feature].get() for feature in numerical_features}
    
    # Get values from checkboxes
    binary_values = {feature: binary_vars[feature].get() for feature in binary_features}
    
    # Print the values to the console (you can process them further here)
    print("Categorical values:", selected_protocol, selected_service, selected_flag)
    print("Numerical values:", numerical_values)
    print("Binary values:", binary_values)

        # combine all the values into a single dictionary
    input_data = {**numerical_values, **binary_values}
    input_data['protocol_type'] = selected_protocol
    input_data['service'] = selected_service
    input_data['flag'] = selected_flag

    # order the values according to the columns order
    input_data = {col: input_data[col] for col in columns}

    # usa lo scaler sulle colonne numeriche
    input_data_scaled = pd.DataFrame(input_data, index=[0])
    input_data_scaled[numerical_features] = scaler.transform(input_data_scaled[numerical_features])

    # usa l'encoder sulle colonne categoriche
    input_data_encoded = input_data_scaled.copy()
    input_data_encoded['protocol_type'] = encoder_protocol.transform(input_data_scaled['protocol_type'])
    input_data_encoded['service'] = encoder_service.transform(input_data_scaled['service'])
    input_data_encoded['flag'] = encoder_flag.transform(input_data_scaled['flag'])
    print(input_data_encoded)
    prediction = model.predict(input_data_encoded)
    if prediction == 1:
        result = "Normal"
    else:
        result = "Anomalous"
    messagebox.showinfo("Prediction Result", f"The traffic is: {result}")

# Create the main window
root = tk.Tk()
root.title("Intrusion Detection Classification")

# Top: Dropdown menus for categorical features
top_frame = tk.Frame(root)
top_frame.pack(pady=10)

protocol_type_var = tk.StringVar(value='tcp')
service_var = tk.StringVar(value='http')
flag_var = tk.StringVar(value='SF')

tk.Label(top_frame, text="Protocol Type").grid(row=0, column=0)
protocol_menu = ttk.Combobox(top_frame, textvariable=protocol_type_var, values=categorical_features['protocol_type'])
protocol_menu.grid(row=0, column=1)

tk.Label(top_frame, text="Service").grid(row=1, column=0)
service_menu = ttk.Combobox(top_frame, textvariable=service_var, values=categorical_features['service'])
service_menu.grid(row=1, column=1)

tk.Label(top_frame, text="Flag").grid(row=2, column=0)
flag_menu = ttk.Combobox(top_frame, textvariable=flag_var, values=categorical_features['flag'])
flag_menu.grid(row=2, column=1)

# Center: Entry fields for numerical features
center_frame = tk.Frame(root)
center_frame.pack(pady=10)

idx = 0
numerical_vars = {}
for i in range(0, 8):
    for j in range(0, 8, 2):
        if idx >= len(numerical_features):
            break
        tk.Label(center_frame, text=numerical_features[idx]).grid(row=i, column=j)
        var = tk.StringVar(value='0')
        entry = tk.Entry(center_frame, textvariable=var)
        entry.grid(row=i, column=j+1)
        numerical_vars[numerical_features[idx]] = var
        idx += 1
        if idx >= len(numerical_features):
            break

# for idx, feature in enumerate(numerical_features):
#     tk.Label(center_frame, text=feature).grid(row=idx, column=0)


# Bottom: Checkboxes for binary features
bottom_frame = tk.Frame(root)
bottom_frame.pack(pady=10)

i = 0
binary_vars = {}
for idx, feature in enumerate(binary_features):
    var = tk.IntVar(value=0)
    checkbox = tk.Checkbutton(bottom_frame, text=feature, variable=var)
    checkbox.grid(row=40, column=i)
    i += 1
    binary_vars[feature] = var

# Process button
process_button = tk.Button(root, text="Submit", command=process_input)
process_button.pack(pady=10)

# Start the GUI loop
root.mainloop()












# # Create an entry field for custom data
# custom_data_label = tk.Label(root, text="Enter Review Text:", font=default_font)
# custom_data_label.grid(row=0, column=0, padx=10, pady=10, sticky='w')

# custom_data_entry = tk.Text(root, height=10, width=50, font=default_font)
# custom_data_entry.grid(row=1, column=0, padx=10, pady=5)

# verified_purchase_var = tk.IntVar(value=1)  # Default is 1 (Verified)

# # Create a Checkbutton to toggle Verified Purchase
# verified_purchase_checkbutton = tk.Checkbutton(root, text="Verified Purchase", font=default_font, variable=verified_purchase_var)
# verified_purchase_checkbutton.grid(row=2, column=0, padx=10, pady=5)

# # Label to display prediction results
# prediction_result_label = tk.Label(root, text="", font=default_font, fg="blue")
# prediction_result_label.grid(row=4, column=0, padx=10, pady=10)

# # Function to predict custom data
# def predict_custom_data():
#     try:
#         # Get custom data from entry field
#         text = custom_data_entry.get("1.0", tk.END).strip()
#         verified_purchase = verified_purchase_var.get()

#         df = pd.DataFrame({
#             'REVIEW_TEXT': [text],
#             'VERIFIED_PURCHASE': [verified_purchase],
#         })
#         df['Sentence_Embeddings'] = df['REVIEW_TEXT'].apply(lambda x: generate_word_embeddings(x, model))
#         predictions = pipeline_model.predict(df)
#         prediction = 'Fake' if predictions[0] == '__label1__' else 'Real'
#         prediction_result_label.config(text=f"Prediction: {prediction}")
#     except Exception as e:
#         messagebox.showerror("Error", str(e))

# # Create a button to predict custom data
# custom_predict_button = tk.Button(root, text="Predict Review", font=default_font, command=predict_custom_data, bg="green", fg="white", width=20)
# custom_predict_button.grid(row=3, column=0, padx=10, pady=10)

# # Run the application
# root.mainloop()
