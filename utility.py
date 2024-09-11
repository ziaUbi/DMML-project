from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import TargetEncoder
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
           'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
           'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
           'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
           'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
           'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
           'dst_host_srv_rerror_rate', 'label', 'score']

nominal_features = ['protocol_type', 'service', 'flag']
binary_features = ['land', 'logged_in', 'root_shell', 'su_attempted', 'is_host_login', 'is_guest_login']
numeric_features = [feature for feature in columns if feature not in nominal_features + binary_features + ['label', 'score', 'num_outbound_cmds']]

def assign_attack_type(label):
    attack_dict = { 'normal': 'normal',
                                   
                'neptune': 'dos', 'back': 'dos', 'land': 'dos',
                'pod': 'dos', 'smurf': 'dos', 'teardrop': 'dos', 'mailbomb': 'dos',
                'apache2': 'dos', 'processtable': 'dos', 'udpstorm': 'dos', 'worm': 'dos',

                'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
                'mscan': 'probe', 'saint': 'probe', 

                'ftp_write': 'r2l', 'guess_passwd': 'r2l','imap': 'r2l', 'multihop': 'r2l', 'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l',
                'warezmaster': 'r2l', 'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l',
                'snmpguess': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l', 'httptunnel': 'r2l',

                'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r',
                'ps': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r'
                }
    return attack_dict[label]

def oh_encoder(train_df, test_df, nominal_features):
    enc = OneHotEncoder()
    train_encoded = enc.fit_transform(train_df[nominal_features]).toarray()
    test_encoded = enc.transform(test_df[nominal_features]).toarray()
    new_columns = []
    for i, feature in enumerate(nominal_features):
        new_columns.extend([f"{feature}_{str(cat)}" for cat in enc.categories_[i]])

    train_ohe = train_df.drop(nominal_features, axis=1)
    train_ohe = pd.concat([train_ohe, pd.DataFrame(train_encoded, columns=new_columns)], axis=1)

    test_ohe = test_df.drop(nominal_features, axis=1)
    test_ohe = pd.concat([test_ohe, pd.DataFrame(test_encoded, columns=new_columns)], axis=1)

    return train_ohe, test_ohe

def t_encoder(train_df, test_df, nominal_features):
    enc = TargetEncoder()
    train_encoded = enc.fit_transform(train_df[nominal_features], train_df['label'])
    test_encoded = enc.transform(test_df[nominal_features])

    train_t = train_df.drop(nominal_features, axis=1)
    train_t = pd.concat([train_t, pd.DataFrame(train_encoded, columns=nominal_features)], axis=1)

    test_t = test_df.drop(nominal_features, axis=1)
    test_t = pd.concat([test_t, pd.DataFrame(test_encoded, columns=nominal_features)], axis=1)

    return train_t, test_t

def scaler(train_df, test_df, scaler = MinMaxScaler()):
    train_scaled = scaler.fit_transform(train_df[numeric_features])
    test_scaled = scaler.transform(test_df[numeric_features])

    train_ss = train_df.drop(numeric_features, axis=1)
    train_ss = pd.concat([train_ss, pd.DataFrame(train_scaled, columns=numeric_features)], axis=1)

    test_ss = test_df.drop(numeric_features, axis=1)
    test_ss = pd.concat([test_ss, pd.DataFrame(test_scaled, columns=numeric_features)], axis=1)

    return train_ss, test_ss

class Dataset:    
    def __init__(self, data):
        self.data = data
        self.data.columns = columns
        # 'su_attempted' dovrebbe essere binario ma ha 3 valori. Sostituiamo '2.0' con '0.0'
        self.data['su_attempted'] = self.data['su_attempted'].replace(2, 0)
        # 'num_outbound_cmds' ha sempre lo stesso valore quindi possiamo dropparla
        self.data = self.data.drop('num_outbound_cmds', axis=1)

    def get_data(self):
        return self.data
    
    def get_label2(self):
        self.label2 = self.data.copy()
        self.label2['label'] = self.label2['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
        return self.label2
    
    def get_label5(self):
        self.label5 = self.data.copy()
        self.label5['label'] = self.label5['label'].apply(lambda x: assign_attack_type(x))
        return self.label5