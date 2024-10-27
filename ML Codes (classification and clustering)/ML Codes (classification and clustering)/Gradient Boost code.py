import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, plot_confusion_matrix
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import RepeatedStratifiedKFold
from pydotplus import graph_from_dot_data
from IPython.display import Image
from sklearn.tree import export_graphviz
from sklearn import tree
from sklearn.metrics import mean_squared_error
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import RandomizedSearchCV
from sklearn.metrics import accuracy_score, confusion_matrix, plot_confusion_matrix, recall_score, precision_score, \
    f1_score, fbeta_score
import xgboost as xgb
from sklearn.metrics import mean_squared_error
from sklearn import metrics

df = pd.read_csv("/home/tytler/Project Work/Extracted Data/Resultant/Random Forest/Dataset 1/Merged Dataset 1 (copy).csv", header=0)

df = pd.get_dummies(df, columns=['Is IP as Host name', 'Is .exe present',
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
                                  'Is title tag empty' ], drop_first=True)

X = df.loc[:, df.columns != 'Label']  # Consider all columns without Start_Tech_Oscar
y = df['Label']  # Consider Start_|Tech_Oscar as a label
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=4)

parameters = {
    "loss": ["deviance", "exponential"],
    "learning_rate": [0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.25, 0.3],
    "min_samples_split": np.linspace(0.1, 0.5, 12),
    "min_samples_leaf": np.linspace(0.1, 0.5, 12),
    "max_depth": [3, 5, 8, 10, 15, 20, 25],
    "max_features": ["log2", "sqrt", "auto"],
    "criterion": ["friedman_mse", "mae", "mse"],
    "subsample": [0.5, 0.618, 0.8, 0.85, 0.9, 0.95, 1.0],
    "n_estimators": [100]
}

cv = RepeatedStratifiedKFold(n_splits=10, n_repeats=4, random_state=3)
RD_search = GridSearchCV(GradientBoostingClassifier(), parameters, cv=cv, n_jobs=-1, scoring='accuracy')
RD_result = RD_search.fit(X_train, y_train)
print("Best: %f using %s" % (RD_result.best_score_, RD_result.best_params_))

# Train with best params
gbc_clf2 = GradientBoostingClassifier(learning_rate=RD_result.best_params_.get('learning_rate'),
                                      loss=RD_result.best_params_.get('loss'),
                                      min_samples_split=RD_result.best_params_.get('min_samples_split'),
                                      min_samples_leaf=RD_result.best_params_.get('min_samples_leaf'),
                                      max_depth=RD_result.best_params_.get('max_depth'),
                                      max_features=RD_result.best_params_.get('max_features'),
                                      criterion=RD_result.best_params_.get('criterion'),
                                      subsample=RD_result.best_params_.get('subsample'),
                                      n_estimators=RD_result.best_params_.get('n_estimators'))
gbc_clf2.fit(X_train, y_train)
acc_train = accuracy_score(y_train, gbc_clf2.predict(X_train)) * 100
acc_test = accuracy_score(y_test, gbc_clf2.predict(X_test)) * 100
print("accuracy of train phase is {:.4f}".format(acc_train))
print("accuracy of test phase is {:.4f}".format(acc_test))

y_train_pred = gbc_clf2.predict(X_train)
y_test_pred = gbc_clf2.predict(X_test)
print("Mean Squre Error - train {:.4f}".format(mean_squared_error(y_train, y_train_pred)))
print("Mean Squre Error - test {:.4f}".format(mean_squared_error(y_test, y_test_pred)))

plot_confusion_matrix(gbc_clf2, X_test, y_test)
plt.show()
tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()

print("-------------------------------------Metrics------------------------------------------")
print("Test accuracy score {:.4f}".format(accuracy_score(y_test, y_test_pred) * 100))
print("Test Recall {:.4f}".format(recall_score(y_test, y_test_pred) * 100))
print("Test Precision {:.4f}".format(precision_score(y_test, y_test_pred) * 100))
print("Test F1 Score {:.4f}".format(f1_score(y_test, y_test_pred) * 100))
print("Test F2 Score {:.4f}".format(fbeta_score(y_test, y_test_pred, beta=2.0) * 100))

print("--------------------------TPR, TNR, FPR, FNR------------------------------------------")
TPR = tp / (tp + fn)
TNR = tn / (tn + fp)
FPR = fp / (fp + tn)
FNR = fn / (fn + tp)
print("TPR {:.4f}".format(TPR))
print("TNR {:.4f}".format(TNR))
print("FPR {:.4f}".format(FPR))
print("FNR {:.4f}".format(FNR))















