import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import mglearn

df = pd.read_csv("/home/tytler/Project Work/Extracted Data/Merged Dataset 6.csv", header =0)

from sklearn.cluster import KMeans
wcss = []
for i in range(1, 11):
    kmeans = KMeans(n_clusters = i, init = 'k-means++', random_state = 42)
    kmeans.fit(df)
    wcss.append(kmeans.inertia_)

plt.plot(range(1, 11), wcss)
plt.xlabel('Number of clusters')
plt.ylabel('Error')
plt.show()

kmeans = KMeans(n_clusters = 2, init = 'k-means++', random_state = 42)
y_kmeans = kmeans.fit_predict(df)


plt.scatter(df.iloc[:, 0], df.iloc[:, 1], c=kmeans.labels_, cmap=mglearn.cm3, s=40)
plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1],
marker='^', s=100, linewidth=2, c=[0, 1], cmap=mglearn.cm3)

plt.scatter(df.iloc[y_kmeans == 0, 0], df.iloc[y_kmeans == 0, 1], s = 50, c = 'red', label = 'Benign')
plt.scatter(df.iloc[y_kmeans == 1, 0], df.iloc[y_kmeans == 1, 1], s = 50, c = 'blue', label = 'Malicious')
#plt.scatter(kmeans.cluster_centers_[:, 0], kmeans.cluster_centers_[:, 1], s = 0, c = 'black', label = 'Centroids')
plt.xlabel('')
plt.ylabel('')
plt.legend()

plt.show()

print("Executed")


