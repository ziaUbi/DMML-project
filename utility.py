import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder, MinMaxScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest,  SequentialFeatureSelector, RFE
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.decomposition import PCA

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

def l_encoder(train_df, test_df, nominal_features):
    enc = LabelEncoder()
    for feature in nominal_features:
        train_df[feature] = enc.fit_transform(train_df[feature])
        test_df[feature] = enc.transform(test_df[feature])

    return train_df, test_df

def scaler(train_df, test_df, numeric_features, scaler = MinMaxScaler()):
    train_df[numeric_features] = scaler.fit_transform(train_df[numeric_features])
    test_df[numeric_features] = scaler.transform(test_df[numeric_features])

    return train_df, test_df

def get_best_features(train_data, test_data, score_func, k):
    X = train_data.drop(['label'], axis=1)
    y = train_data['label']
    selector = SelectKBest(score_func=score_func, k = k).fit(X, y)
    X_train_selected = selector.transform(X)
    X_test_selected = selector.transform(test_data.drop(['label'], axis=1))
    selected_features = X.columns[selector.get_support()]
    print(selected_features)
    return X_train_selected, X_test_selected

def cfs(train_data, test_data):
    X_train = train_data.drop(['label'], axis=1)
    X_test = test_data.drop(['label'], axis=1)
    corr_matrix = X_train.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    to_drop = [column for column in upper.columns if any(upper[column] > 0.9)]
    X_train = X_train.drop(to_drop, axis=1)
    X_test = X_test.drop(to_drop, axis=1)
    return X_train, X_test

def rfe(train_data, test_data, k):
    X = train_data.drop(['label'], axis=1)
    y = train_data['label']
    X_test = test_data.drop(['label'], axis=1)

    model = RandomForestClassifier()
    rfe = RFE(model, 
              n_features_to_select=k).fit(X, y)
    X_train_selected = rfe.transform(X)
    X_test_selected = rfe.transform(X_test)
    print(X.columns[rfe.get_support()])
    return X_train_selected, X_test_selected

def sfs(train_data, test_data, k):
    X = train_data.drop(['label'], axis=1)
    y = train_data['label']
    X_test = test_data.drop(['label'], axis=1)

    model = RandomForestClassifier()
    sfs = SequentialFeatureSelector(model, 
                                    cv = StratifiedKFold(n_splits=5, random_state=123, shuffle=True),
                                    scoring = 'accuracy', 
                                    direction='forward', 
                                    n_features_to_select=k).fit(X, y)
    X_train_selected = sfs.transform(X)
    X_test_selected = sfs.transform(X_test)
    print(X.columns[sfs.get_support()])
    return X_train_selected, X_test_selected

def pca(train_data, test_data, k):
    X = train_data.drop(['label'], axis=1)
    X_test = test_data.drop(['label'], axis=1)

    pca = PCA(n_components=k)
    X_train_pca = pca.fit_transform(X)
    X_test_pca = pca.transform(X_test)
    
    print(X_train_pca.shape)
    print(pca.components_)
    print(pca.explained_variance_ratio_)
    print(pca.explained_variance_)
    print(pca.singular_values_)
    print(pca.singular_values_.sum())

    return X_train_pca, X_test_pca

class Dataset:    
    def __init__(self, data, columns):
        self.data = data
        self.data.columns = columns
        self.data['su_attempted'] = self.data['su_attempted'].replace(2, 0)
        self.data = self.data.drop('num_outbound_cmds', axis=1)
        self.data = self.data.drop('score', axis=1)

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