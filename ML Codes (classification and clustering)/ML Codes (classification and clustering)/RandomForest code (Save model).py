import re
import pickle
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, plot_confusion_matrix, recall_score, precision_score,f1_score,fbeta_score
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn import tree
from sklearn.metrics import accuracy_score , confusion_matrix , plot_confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import mean_squared_error

df = pd.read_csv("/home/tytler/Project Work/Extracted Data/Merged Dataset (copy)/Merged Dataset 3 (copy).csv", header =0)

regex = re.compile(r"\[|\]|<", re.IGNORECASE)
df.columns = [regex.sub("_", col) if any(x in str(col) for x in set(('[', ']', '<'))) else col for col in df.columns.values]

df = pd.get_dummies(df, columns =['Is IP as Host name', 'Is .exe present',
                                  'FTP used', 'Is www present','.js used',
                                  'Files in URL', 'css used', 'Is Hashed ','TLD',
                                  'File Extention','Hyphenstring', 'Homoglyph',
                                  'Vowel string', 'Bitsquatting', 'Insertion string', 					   
                                  'Omission', 'Repeatition', 'Replacement',
                                  'Subdomain', 'Transposition', 'Addition string',
                                  'TLD in Subdomain','TLD in path',
                                  'https in host name','Word based distribution',
                                  'Is English word','Is Meaningful','Is Pronounceable',
                                  'Is random', 'IP Address', 'ASN Number',
                                  'ASN Country Code', 'ASN CIDR', 'ASN Postal Code',
                                  'ASN creation date', 'ASN updation date',
                                  'Fake link in status bar', 'Right click disable',
                                  'Popup window', 'mailto: present', 'Frame tag present', 
                                  'Is title tag empty'], drop_first = True )


X = df.loc[:,df.columns!="Label"]
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.21, random_state = 0)

#Ignore all warning messages
warnings.filterwarnings("ignore")

rf_clf = RandomForestClassifier (random_state = 42)

params_grid = {
               'max_depth': [5, 8, 10, 15, 20, 25, 30, 50],
               'max_features': ['log2','sqrt',0.25,0.5, .66, 1.0],
                'min_samples_leaf': [1,25,50,70],
               'min_samples_split': [2, 5, 10, 20]
               }

grid_search = GridSearchCV(estimator = rf_clf, param_grid = params_grid ,n_jobs = -1, cv = 2, scoring = 'accuracy')
grid_result = grid_search.fit(X_train, y_train)

gbc_clf2 = RandomForestClassifier(#nthread = grid_result.best_params_.get('nthread'),
                     max_depth = grid_result.best_params_.get('max_depth'),
                     max_features = grid_result.best_params_.get('max_features'),
                     min_samples_leaf = grid_result.best_params_.get('min_samples_leaf'),
                     min_samples_split = grid_result.best_params_.get('min_samples_split')
                      )

gbc_clf2.fit(X_train, y_train)

with open('model_pickle','wb') as f:
    pickle.dump(gbc_clf2,f)

acc_train = accuracy_score(y_train, gbc_clf2.predict(X_train)) *100
acc_test = accuracy_score(y_test, gbc_clf2.predict(X_test)) *100
print("accuracy of train phase is {:.4f}".format(acc_train))
print("accuracy of test phase is {:.4f}".format(acc_test))

y_train_pred = gbc_clf2.predict(X_train)
y_test_pred = gbc_clf2.predict(X_test)
print("Mean Squre Error - train {:.4f}".format(mean_squared_error(y_train,y_train_pred)))
print("Mean Squre Error - test {:.4f}".format(mean_squared_error(y_test,y_test_pred)))

plot_confusion_matrix(gbc_clf2, X_test, y_test)
plt.show()
tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()

print("-------------------------------------Metrics------------------------------------------")
print("Test accuracy score {:.4f}".format(accuracy_score(y_test, y_test_pred)*100))
print("Test Recall {:.4f}".format(recall_score(y_test, y_test_pred)*100))
print("Test Precision {:.4f}".format(precision_score(y_test, y_test_pred)*100))
print("Test F1 Score {:.4f}".format(f1_score(y_test, y_test_pred)*100))
print("Test F2 Score {:.4f}".format(fbeta_score(y_test, y_test_pred, beta=2.0)*100))

print("--------------------------TPR, TNR, FPR, FNR------------------------------------------")
TPR = tp/(tp+fn)
TNR = tn/(tn+fp)
FPR = fp/(fp+tn)
FNR = fn/(fn+tp)
print("TPR {:.4f}".format(TPR))
print("TNR {:.4f}".format(TNR))
print("FPR {:.4f}".format(FPR))
print("FNR {:.4f}".format(FNR))
