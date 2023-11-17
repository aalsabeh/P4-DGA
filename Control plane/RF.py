# take top 500 DGA samples (based on the len of their events)
# take all normal samples from CTU (they are approximately 80)
# take the rest of the samples from 10 Days campus (try randomly, try based on top length)

import csv
import ast
import matplotlib.pyplot as plt
import json
import numpy as np
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score


events = [1, 2, 3, 4, 5, 6, 8, 10]
# events = [3]
'''
 MALWARE SAMPLES 
'''
def train_RF_model(event = 4):
    DGA_dataset_dir = "dataset/DGA_dataset"

    og_event = event
    event = event*2 - 1 # since we have the interarrival time now

    ''' 
    DGA files:  VT_DGA_30min_dataset_filtered.csv, 
                VT_DGA_30min_dataset_ec2_filtered.csv, 
                triage_pcaps_filtered.csv
    '''

    DGA_files = [DGA_dataset_dir + '/DGA_triage_2.csv', DGA_dataset_dir + '/DGA_VT1_2.csv', DGA_dataset_dir + '/DGA_VT2_2.csv']
    all_dga_ratios = []
    all_dga_nxds = []
    all_dga_rnd_nxds = []
    all_dga_iarrivals = []

    for dgafile in DGA_files:
        
        with open(dgafile) as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',')
            for row in csv_reader:
                file_name = row[0]
                
                minimum_index = min(event, len(row)-1)
                event_row = ast.literal_eval(row[minimum_index])
                        
                ratio = event_row[3] / (event_row[2] + 1)
                nxds = event_row[0]
                rnd_nxds = event_row[1]
                # interarrival time (from 0 to event)
                iarrivals = []
                for i in range(1, minimum_index+1):
                    if i%2 == 0: # interarrival time
                        iarrivals.append(int(row[i]))

                all_dga_nxds.append(nxds)
                all_dga_rnd_nxds.append(rnd_nxds)
                all_dga_ratios.append(ratio)
                all_dga_iarrivals.append(sum(iarrivals)) # !!


    X1_DGA = all_dga_ratios
    X2_DGA = all_dga_rnd_nxds
    X3_DGA = all_dga_nxds
    X4_DGA = all_dga_iarrivals
        
        
        
    DGA_features = (X1_DGA, X2_DGA, X3_DGA, X4_DGA)
    #     DGA_features = (X1_DGA, X3_DGA) # ratio, NXD
    #     DGA_features = (X1_DGA, X2_DGA) # ratio, rnd_NXD
    #     DGA_features = (X2_DGA, X3_DGA) # randomness, NXD
    #     DGA_features = (X1_DGA, X4_DGA) # ratio, iarrivals
    #     DGA_features = (X1_DGA, X2_DGA, X3_DGA)

    X = np.column_stack(DGA_features)
        # X = np.column_stack((X1_DGA, X2_DGA, X3_DGA, X4_DGA))
    y = np.ones(len(X1_DGA))
        

    '''
        CTU_42, ..., CTU54 NORMAL SAMPLES 
    ''' 
    normal_dataset_dir = "dataset/normal_dataset"
    all_norm_ratios = []
    all_norm_nxds = []
    all_norm_rnd_nxds = []
    all_norm_arrivals = []
    normal_data = {} 


    # for ctu_file in ['normal_CTU42.csv', 'normal_CTU43.csv', 'normal_CTU44.csv']:
    for i_count in range(42, 55):
        ctu_file = normal_dataset_dir + '/normal_CTU' + str(i_count) + '_2.csv'
        with open(ctu_file) as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',')
            for row in csv_reader:
    #                 if len(row) > 10:
                file_name = row[0]
                
                minimum_index = min(event, len(row)-1)
                event_row = ast.literal_eval(row[minimum_index])
                
                ratio = event_row[3] / (event_row[2] + 1)
                nxds = event_row[0]
                rnd_nxds = event_row[1]
                iarrivals = [] 
                for i in range(1, minimum_index+1):
                    if i%2 == 0: 
                        iarrivals.append(int(row[i]))
                all_norm_nxds.append(nxds)
                all_norm_rnd_nxds.append(rnd_nxds)
                all_norm_ratios.append(ratio)
                all_norm_arrivals.append(sum(iarrivals))



    X1_normal = all_norm_ratios
    X2_normal = all_norm_rnd_nxds
    X3_normal = all_norm_nxds
    X4_normal = all_norm_arrivals


    normal_features = (X1_normal, X2_normal, X3_normal, X4_normal)
    #     normal_features = (X1_normal, X3_normal) # ratio, NXD
    #     normal_features = (X1_normal, X3_normal) # ratio, rnd_NXD
    #     normal_features = (X2_normal, X3_normal) # randomness, NXD
    #     normal_features = (X1_normal, X4_normal) # ratio, iarrivals
    #     normal_features = (X1_normal, X2_normal, X3_normal)


    X = np.append(X, np.column_stack(normal_features), axis=0)
    y = np.append(y, np.zeros(len(X1_normal)))


    #     '''
    # Random forest training
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)
    sc = StandardScaler()
    X_train = sc.fit_transform(X_train)
    X_test = sc.transform(X_test)
    clf = RandomForestClassifier(max_depth=10, random_state=0)
    clf.fit(X_train, y_train)

    return clf, sc
    # y_pred = clf.predict(X_test)


    # print("CLASSIFICATION REPORT ", classification_report(y_test,y_pred))
    # print("ACCURACY SCORE ", accuracy_score(y_test, y_pred))

    # # feature importance
    # print("Feature Importance ", clf.feature_importances_)


