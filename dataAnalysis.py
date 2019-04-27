import os, re
import pandas as pd
import matplotlib.pyplot as plt
colors = ['green', 'yellow', 'k', 'maroon', 'blue', 'white']


class addGraph():
    def __init__(self, path):
        self.path = path

    def ClusterInfo(self, summary_pd):
        summary_pd2 = pd.DataFrame({'Count': summary_pd.groupby(["Model"]).size()}).reset_index()
        try:
            if not summary_pd2.empty:
                x = summary_pd2.Model
                y = summary_pd2.Count
                fig, ax = self.appearance(x,y)
                name = 'None'
                if summary_pd.Clustered_.all() == 'true':
                    name = 'Cluster_Summary'
                elif summary_pd.Clustered_.all() == 'false':
                    name = 'NonCluster_Summary'
                ax.set_title(name)
                ax.set_xlabel('Models')
                name = name + '.png'
                fig.savefig(os.path.join(self.path, name ))
                return True
        except Exception as e:
            return False

    def appearance(self,x,y):
        fig, ax = plt.subplots(figsize=(15, 15))
        ax.bar(x, y, width=.05, color=colors)
        fig.set_facecolor('.7')
        ax.set_facecolor('#DCDCDC')
        ax.set_xticklabels(x, rotation=45)
        return fig, ax

    def shareInfo(self, Vol_Df, clus):
        try:
            if clus == 'true':
                uniq_cluster = Vol_Df.Cluster.unique()
                new_util = []
                for cluster in uniq_cluster:
                    new_util.append({'Cluster': cluster,
                             'Total_Node_cap_KB': Vol_Df[(Vol_Df.Cluster ==cluster) & (~Vol_Df.Filesystem.str.contains('vol0'))].Total_KB.sum(),
                             'Node_VOL_0_cap': Vol_Df[(Vol_Df.Cluster ==cluster) & (Vol_Df.Filesystem.str.contains('vol0/'))].Total_KB.sum(),
                             'No_FileSystems': Vol_Df[(Vol_Df.Cluster == cluster) & (~Vol_Df.Filesystem.str.contains('vol0/'))].Filesystem.count(), })
                Util_volumes = pd.DataFrame(new_util)
                files = ['Clus_Vol_Filesystems.png', 'Clus_Vol_Space.png']
            elif clus == 'false':
                uniq_nodes = Vol_Df.Node.unique()
                new_util = []
                for node in uniq_nodes:
                    new_util.append({'Node': node,
                             'Total_Node_cap_KB': Vol_Df[(Vol_Df.Node ==node) & (~Vol_Df.Filesystem.str.contains('vol0'))].Total_KB.sum(),
                             'Node_VOL_0_cap': Vol_Df[(Vol_Df.Node ==node) & (Vol_Df.Filesystem.str.contains('vol0/'))].Total_KB.sum(),
                             'No_FileSystems': Vol_Df[(Vol_Df.Node ==node) & (~Vol_Df.Filesystem.str.contains('vol0/'))].Filesystem.count(), })
                Util_volumes = pd.DataFrame(new_util)
                files = ['NonClus_Vol_Filesystems.png', 'NonClus_VolSpace.png']
        except Exception as e:
            Util_volumes = pd.DataFrame()

        try:
            if not Util_volumes.empty:
                for y,n  in zip( [Util_volumes.No_FileSystems, Util_volumes.Total_Node_cap_KB/1048576 ],files ):
                    if Vol_Df.Clustered_.all() == 'true':
                        x = Util_volumes.Cluster
                        fig, ax = self.appearance(x,y)
                        ax.set_title(n[4:-4])
                        ax.set_xlabel('Clusters')
                        name = 'Cluster_Volumes'

                    elif Vol_Df.Clustered_.all() == 'false':
                        x = Util_volumes.Node
                        fig, ax = self.appearance(x, y)
                        ax.set_title(n[8:-4])
                        ax.set_xlabel('Nodes')
                        name = 'NonCluster_Volumes'

                    fig.savefig(os.path.join(self.path, n ))
                return True
            elif Util_volumes.empty():
                raise ValueError('No Data Found')
        except Exception as e:
            return False
