import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, plot_confusion_matrix, recall_score, precision_score,f1_score,fbeta_score
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import RepeatedStratifiedKFold
from pydotplus import graph_from_dot_data
from IPython.display import Image
from sklearn.tree import export_graphviz
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier
import xgboost as xgb
from sklearn.metrics import mean_squared_error
from sklearn import metrics
from sklearn.model_selection import RandomizedSearchCV

df = pd.read_csv("/home/tytler/Project Work/Extracted Data/Resultant/XGBoost/Dataset 6/Merged Dataset 6 (copy).csv", header =0)

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

X = df.loc[:, df.columns != 'Label'] # Consider all columns without Start_Tech_Oscar
y = df['Label'] # Consider Start_|Tech_Oscar as a label
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.37, random_state = 3)

xgb_model = xgb.XGBClassifier()
parameters = {#'nthread':[8], #when use hyperthread, xgboost may become slower
              'objective':['binary:logistic'],
              'learning_rate': [1e-3, 1e-2, 1e-1, 0.5, 1.], #so called `eta` value
              'max_depth': np.arange(1, 11, 1),
              'min_child_weight': np.arange(1, 21, 1),
              'silent': [1],
              'subsample': np.arange(0.05, 1.01, 0.05),
              'colsample_bytree': [0.6, 0.8, 1.0],
              'n_estimators': [5, 100, 500], #number of trees, change it to 1000 for better results
              'missing':[-999],
              'gamma':[0.1, 0.2, 0.3, 0.4, 0.5],
              'seed': [1337],
              'n_jobs': [1], # replace "nthread"
              'verbose': [0]
              #'random_state': [42]

              }

cv = RepeatedStratifiedKFold(n_splits=10, n_repeats=2, random_state=19)
RD = GridSearchCV(xgb_model, parameters, n_jobs=1, cv=cv, scoring='accuracy',verbose=0, refit=True)
RD_result = RD.fit(X_train, y_train)

from pprint import pprint

pprint("Best: %f using %s" % (RD.best_score_, RD.best_params_))
pprint(RD.best_estimator_)

gbc_clf2 = xgb.XGBClassifier(#nthread = RD.best_params_.get('nthread'),
                     objective = RD.best_params_.get('objective'),
                     learning_rate = RD.best_params_.get('learning_rate'),
                     max_depth = RD.best_params_.get('max_depth'),
                     min_child_weight = RD.best_params_.get('min_child_weight'),
                     silent = RD.best_params_.get('silent'),
                     subsample = RD.best_params_.get('subsample'),
                     colsample_bytree = RD.best_params_.get('colsample_bytree'),
                     n_estimators = RD.best_params_.get('n_estimators'),
                     missing = RD.best_params_.get('missing'),
                     seed = RD.best_params_.get('seed'),
                     gamma = RD.best_params_.get('gamma'),
                     n_jobs=1,
                     random_state=42)


gbc_clf2.fit(X_train, y_train)

with open('model_pickle','wb') as f:
    pickle.dump(gbc_clf2,f)

xgb.plot_importance(gbc_clf2)
acc_train = accuracy_score(y_train, gbc_clf2.predict(X_train)) *100
acc_test = accuracy_score(y_test, gbc_clf2.predict(X_test)) *100
print("accuracy of train phase is {:.4f}".format(acc_train))
print("accuracy of test phase is {:.4f}".format(acc_test))

# Metrics
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
