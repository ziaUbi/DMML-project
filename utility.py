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

class Dataset:    
    def __init__(self, data):
        self.data = data
        self.label2 = self.data.copy()
        self.label5 = self.data.copy()

    def get_data(self):
        return self.data
    
    def get_label2(self):
        self.label2['label'] = self.label2['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
        return self.label2
    
    def get_label5(self):
        self.label5['label'] = self.label5['label'].apply(lambda x: assign_attack_type(x))
        return self.label5