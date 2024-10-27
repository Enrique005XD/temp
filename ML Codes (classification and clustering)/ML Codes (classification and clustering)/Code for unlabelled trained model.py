import pickle
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

df = pd.read_csv("/home/tytler/Project Work/Extracted Data/unlabelled/o2 (copy).csv", header =0)

X = df.loc[:,df.columns!="Label"]
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.23, random_state = 7)

with open('model_pickle','rb') as f:
    mp = pickle.load(f)

mp.fit(X_train, y_train)

acc_train = accuracy_score(y_train, mp.predict(X_train)) *100
acc_test = accuracy_score(y_test, mp.predict(X_test)) *100
print("accuracy of train phase is {:.4f}".format(acc_train))
print("accuracy of test phase is {:.4f}".format(acc_test))

y_train_pred = mp.predict(X_train)
y_test_pred = mp.predict(X_test)
print("Mean Squre Error - train {:.4f}".format(mean_squared_error(y_train,y_train_pred)))
print("Mean Squre Error - test {:.4f}".format(mean_squared_error(y_test,y_test_pred)))

plot_confusion_matrix(mp, X_test, y_test)
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
