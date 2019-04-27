"""
#  Author: Siddartha Pillarisetty  [ EMC PROFESSIONAL SERVICES ]
#
#  Date Originally Created: 04/16/18
#  Script language: Python
#  Last Modified Date:
"""

import shutil, os, sys, re, configparser, glob
from urllib.parse import urljoin
import subprocess as SP
import xml.etree.ElementTree as ET
import pandas as pd
from io import StringIO
import dataAnalysis as DV
import pdb


##################### Working Patterns ###########
CIFS_para_comp = re.compile('^=====\s([\w_-]+).+?-----------(\n.+?)(?=\n^=====\s[\w_-]+)', re.MULTILINE|re.DOTALL)
CIFS_Share_comp = re.compile('(^\w[\w&$\s-]+)(/[/\w-]*)(\s+[\w\s./-]+|\n)\t\t(.*?)(?=\n\w)', re.MULTILINE|re.DOTALL)
vf_old = re.compile('(^[\w_-]+)\s+(\w+)')
vf_allowed_proto_comp = re.compile('Allowed:\s+proto\=(\w+)')
vf_path_comp = re.compile('Path:\s+(.*)')
vf_IPadd = re.compile('IP address:\s+(.+?)\s+')
vf = re.compile('(^[\w_-]+)\s+(\w+)(?!.*licensed_feature)')
ntp_comp = re.compile('^(server\s+.*)', re.MULTILINE)
dns_comp = re.compile('^(\d+\.[\d\.]+)\s+(\w+\s?\w+)', re.MULTILINE)
IP_para_comp = re.compile('^([\w_-]+:\s.+?)(?=\n^[\w_-]+:\s.+)', re.MULTILINE|re.DOTALL)
ser_ada_mtu = re.compile('^([\w_-]+):.+?mtu\s(\d+)')
ser_ether = re.compile('ether\s+(.+?)\s')
ser_vf_ipconfig = re.compile('vFiler ID: (\d+)')
ser_inet  = re.compile('inet\s(.+?)\snetmask\s(\w+)\s')
Net_para_comp = re.compile('^([\w_$-]+):\s+(\d+)(.*?)(?=\n^[\w_$-]+:)', re.MULTILINE|re.DOTALL)
Net_Mediatype = re.compile('\t([\w_$-]+):\s+state\s+(\w+).*?mediatype:\s([\w_ -]+)', re.MULTILINE|re.DOTALL)



##################################################

def setup():
    base = os.path.dirname(os.path.abspath( sys.argv[0]))

    settings = configparser.ConfigParser()
    settings._interpolation = configparser.ExtendedInterpolation()
    settings.read( os.path.join(base, 'config.txt') )
    settings.sections()
    path = settings.get('Setup', 'path')
    pathplus = os.path.join(path, 'temp')
    loc_7z = settings.get('Setup', 'path_7z').strip()
    if os.path.exists(pathplus):
        shutil.rmtree(pathplus)
    files = glob.glob(path + '/' + '*.7z')
    if not os.path.exists(path) or not os.path.exists(loc_7z):
        print('path dosent exist: ', path, ' or ', loc_7z, 'Exiting!! ')
        sys.exit()
    try:
        Name_locs = re.split('[,\n]+', settings.get('Advanced', 'Name_locs'))
        Name_locs = [x.strip() for x in Name_locs if x is not '']
        Names = re.split('[,\n]+', settings.get('Advanced', 'Names'))
        Names = [x.strip() for x in Names if x is not '']
        Words = re.split('[,\n]+', settings.get('Advanced', 'Words'))
        Words = [x.strip() for x in Words if x is not '']
        base = settings.get('Advanced', 'base').strip()
        ASUP = settings.get('Advanced', 'ASUP').strip()
        Info_Map = {x: [urljoin(base, z + str('//1.0')), os.path.join(pathplus, y)] for x, y, z in
                    zip(Names, Name_locs, Words)}
        nameservice = {x: Info_Map[x][0] for x in Info_Map.keys()}
        nameservice['ASUP'] = ASUP
        return (Name_locs, Names, Words, base, ASUP, files, path, pathplus, loc_7z, Info_Map, nameservice, len(files))
    except Exception as e:
        print('Something failed!! ', e)
        sys.exit()

def all_node_details(call_func):
    def wrapper(*args):
        wrapper.counter += 1
        wrapper.log_file = args[0]
        wrapper.Node_details = call_func(wrapper.log_file)
        if wrapper.counter == 1:
            wrapper.All_nodes.extend(wrapper.Node_details)
        elif wrapper.counter > 1:
            wrapper.All_nodes.extend(wrapper.Node_details)
        return wrapper.All_nodes
    wrapper.counter = 0
    wrapper.All_nodes = []
    return wrapper


def counter_deco(call_func):
    def wrapper( *args):
        wrapper.counter += 1
        wrapper.log_file = args[0]
        wrapper.no_files = args[1]
        wrapper.node = args[3]
        wrapper.cluster = args[2]
        wrapper.cluster_ = args[4]
        CDF, NCDF = call_func(wrapper.log_file, wrapper.no_files, wrapper.cluster, wrapper.node, wrapper.cluster_)
        if wrapper.counter == 1:
            wrapper.C_AllDF = CDF
            wrapper.NC_AllDF = NCDF
        elif wrapper.counter > 1:
            wrapper.C_AllDF = pd.concat([wrapper.C_AllDF, CDF], axis=0,ignore_index=True)
            wrapper.NC_AllDF = pd.concat([wrapper.NC_AllDF, NCDF], axis=0,ignore_index=True)
        return wrapper.C_AllDF, wrapper.NC_AllDF
    wrapper.counter = 0
    wrapper.C_ALLDF = pd.DataFrame()
    wrapper.NC_ALLDF = pd.DataFrame()
    return wrapper


class utils():
    def command(self,run):
        try:
            res = SP.Popen(run, stdout=SP.PIPE, stderr=SP.PIPE)
            o, er = res.communicate()
            return o.decode('utf-8').strip(), er, res.returncode
        except Exception as e:
            print('Running Command "{}" failed with error {}'.format(run, e))

    def renew(self,pathplus):
        if os.path.exists(pathplus):
            shutil.rmtree(pathplus)
        try:
            os.mkdir(pathplus)
        except Exception as e:
            print(e)

    def open_f(self, log_file):
        all_values = []
        if os.access(log_file, os.R_OK):
            with open(log_file, 'r') as fo:
                raw_lines = fo.read()
            return raw_lines
        else:
            return False

@all_node_details
def Node_verbose(*args):
    log_file = args[0]
    with open(log_file, 'r+') as file:
        content = file.read()
        file.seek(0,0)
        file.write('[Node]' + '\n' + content)
    config = configparser.ConfigParser()
    config.read(log_file)
    Details = []
    if config['Node']['X-Netapp-asup-clustered'] == 'true':
        Details.append({'Node' : config['Node']['X-Netapp-asup-hostname'], 'Version': config['Node']['X-Netapp-asup-os-version'],
                'System-ID': config['Node']['X-Netapp-asup-system-id'], 'Clustered_': config['Node']['X-Netapp-asup-clustered'], 'Model': config['Node']['X-Netapp-asup-model-name'], 'LogGenerated_on': config['Node']['X-Netapp-asup-generated-on'],
                'Partner_Node': config['Node']['X-Netapp-asup-partner-hostname'],
                'Serial': config['Node']['X-Netapp-asup-serial-num'], 'Cluster_Name': config['Node']['X-Netapp-asup-cluster-name'] })
    elif config['Node']['X-Netapp-asup-clustered'] == 'false':
        Details.append({'Node' : config['Node']['X-Netapp-asup-hostname'], 'Version': config['Node']['X-Netapp-asup-os-version'],
                'System-ID': config['Node']['X-Netapp-asup-system-id'], 'Clustered_': config['Node']['X-Netapp-asup-clustered'], 'Model': config['Node']['X-Netapp-asup-model-name'], 'LogGenerated_on': config['Node']['X-Netapp-asup-generated-on'],
                'Partner_Node': config['Node']['X-Netapp-asup-partner-hostname'],
                'Serial': config['Node']['X-Netapp-asup-serial-num'], 'Cluster_Name': 'None' })
    return Details


@counter_deco
def get_volumes(*args):
    DF = pd.read_csv(os.path.join(args[0], 'DF.txt'), sep='\s+', header=None)
    DF_S = pd.read_csv(os.path.join(args[0], 'DF-S.txt'), sep='\s+', header=None)
    DF_I = pd.read_csv(os.path.join(args[0], 'DF-I.txt'), sep='\s+', header=None)
    DF.columns = DF.loc[0]
    DF_I.columns = DF_I.loc[0]
    DF_S.columns = DF_S.loc[0]
    DF = DF[1:]
    DF_I = DF_I[1:]
    DF_S = DF_S[1:]
    DF = DF.assign(Index=DF['Filesystem'])
    DF = DF.set_index('Index')
    DF_S = DF_S.assign(Index=DF_S['Filesystem'])
    DF_S = DF_S.set_index('Index')
    DF_I = DF_I.assign(Index=DF_I['Filesystem'])
    DF_I = DF_I.set_index('Index')
    DF_NS = DF[(~DF.Filesystem.str.contains('.snapshot')) & (DF.Filesystem.str != 'snap')]
    DF = DF.assign(Cluster=args[2])
    DF = DF.assign(Node=args[3])
    DF = DF.assign(Clustered_=args[4])
    DF_S = DF_S.assign(Cluster=args[2])
    DF_S = DF_S.assign(Node=args[3])
    DF_S = DF_S.assign(Clustered_=args[4])
    DF_I = DF_I.assign(Cluster=args[2])
    DF_I = DF_I.assign(Node=args[3])
    DF_I = DF_I.assign(Clustered_=args[4])
    DF_I = DF_I.rename(columns={'iused': 'inodes_Used', 'ifree': 'inodes_Free'})
    S_DF = DF.merge(DF_S, on=['Cluster', 'Node', 'Filesystem'])
    SI_DF = S_DF.merge(DF_I, on=['Cluster', 'Node', 'Filesystem', 'Mounted'])
    SI_DF = SI_DF[
        ['Cluster', 'Node', 'Filesystem', 'kbytes', 'used_x', 'avail', 'capacity', 'total-saved', 'deduplicated',
         'inodes_Used', 'inodes_Free', 'Mounted', 'Clustered_']]
    SI_DF.rename(
        columns={'kbytes': 'VOL_CAP_KB', 'used_x': 'USED_KB', 'avail': 'Avail_KB', 'total-saved': 'Total_Saved_KB'
            , 'deduplicated': 'Deduplicated_KB', 'capacity': 'Capacity %'}, inplace=True)

    SI_DF = SI_DF.assign(VOL=SI_DF.Filesystem.map(lambda x: x[5:-1]))
    SI_DF = SI_DF.assign(Total_KB=SI_DF.Deduplicated_KB.apply(pd.to_numeric) +
                                  SI_DF.USED_KB.apply(pd.to_numeric))

    NonC_DF = pd.DataFrame()
    return NonC_DF, SI_DF


@counter_deco
def exports(*args):
    if args[4] == 'true':
        NonC_DF = pd.DataFrame()
        all_values = []
        intr = ['vs', 'vol', 'j_path', 'security_style', 'lang', 'comment', 'policy']
        root = ET.parse(Info_Map['Vol_Info'][1])
        for i in root.findall('ASUP:ROW', nameservice):
            keys = ['Vol_Info:' + str(text) for text in intr]
            values = [i.find(key, nameservice).text for key in keys]
            all_values.append(values)
        columns = ['VServer', 'VOL', 'j_path', 'Security_Style', 'lang', 'comment', 'Policy']
        Clus_DF = pd.DataFrame(all_values, columns=columns)
        Clus_DF = Clus_DF.assign(Cluster=args[2])
        Clus_DF = Clus_DF.assign(Node=args[3])
        return Clus_DF, NonC_DF
    elif args[4] == 'false':
        Clus_DF = pd.DataFrame()
        log_file = os.path.join(args[0], 'exports.txt')
        all_exports = []
        try:
            with open(log_file, 'r') as file:
                lines = file.readlines()
            export = []
            for line in lines:
                search = re.search('^([\w_&/]+)\s+-sec=(.*)', line)
                if search:
                    export = [args[2], args[3], search.group(1), search.group(2) ]
                    all_exports.append(export)
            if len(all_exports) == 0:
                raise ValueError('No Exports found')
            columns=['Cluster', 'Node', 'Export','Security']
            NonC_DF = pd.DataFrame(all_exports, columns=columns )
        except ValueError as e:
            columns = ['Cluster', 'Node', 'Export', 'Security']
            all_exports.append([args[2], args[3], 'None', 'exports.txt - Perhaps all exports are hashed'])
            NonC_DF = pd.DataFrame(all_exports, columns=columns)
        except Exception as e:
            columns=['Cluster', 'Node', 'Export','Security']
            all_exports.append([args[2], args[3], 'None', 'exports.txt - file missing' ] )
            NonC_DF = pd.DataFrame(all_exports, columns=columns )
        return Clus_DF, NonC_DF


@counter_deco
def CIFS_Share(*args):

    if args[4] == 'true':
        NonC_DF = pd.DataFrame()
        all_values = []
        columns = ['Cluster_Name', 'Node_Name', 'VServer', 'CIFS_Server',
                   'ShareName', 'Path', 'Comment']
        intr = ['vserver', 'cifs_server', 'share_name', 'path', 'comment']
        try:
            root = ET.parse(Info_Map['CIFS_share'][1])
            for i in root.findall('ASUP:ROW', nameservice):
                keys = ['CIFS_share:' + str(text) for text in intr]
                values = [i.find(key, nameservice).text for key in keys]
                values.insert(0, args[3])
                values.insert(0, args[2])
                all_values.append(values)
            Clus_DF = pd.DataFrame(all_values, columns=columns)
        except Exception as e:
            all_values.append([args[2], args[3], os.path.split(Info_Map['CIFS_share'][1])[1] + ' - File Missing',
                               'None', 'None', 'None', 'None'])
            Clus_DF = pd.DataFrame(all_values, columns=columns)
        return Clus_DF, NonC_DF

    elif args[4] == 'false':
        share_info = []
        columns = ['Cluster', 'Node', 'vFiler', 'Share', 'Mount', 'Description', 'Permissions']

        log_file = os.path.join(args[0], 'CIFS-SHARES.vfiler.txt')

        try:
            with open(log_file) as file:
                fo = file.read()
            if re.search('Use of vfilers requires multistore licensed_feature option enabled',fo ):
                vfiler = 'False'
            else:
                vfiler = 'Defined'
        except Exception as e:
            share_info.append([args[2], args[3], 'CIFS-SHARES.vfiler.txt  - File Missing', 'None', 'None',
                               'None', 'None'])
            NonC_DF = pd.DataFrame(share_info, columns=columns)
            Clus_DF = pd.DataFrame()
            return Clus_DF, NonC_DF
        if vfiler == 'Defined':
            try:
                with open(log_file) as file:
                    fo = file.read()
                    fo = fo + '===== endoffile'
                if CIFS_para_comp.search(fo):
                    for i in CIFS_para_comp.finditer(fo):
                        vfiler = i.group(1)
                        temp = i.group(2)
                        temp = temp + '\n'+ 'endofstring'
                        for j in CIFS_Share_comp.finditer(temp):
                            perm = re.sub('\t+', ' ', j.group(4))
                            perm = re.sub('[\n]+', ';', perm)
                            share_info.append([args[2], args[3], vfiler, j.group(1), j.group(2), j.group(3), perm])

                else:
                    raise ValueError("No CIFS shares found. Check file manually")
                NonC_DF = pd.DataFrame(share_info, columns=columns)

            except Exception as e:
                share_info.append([args[2], args[3], 'CIFS-SHARES.vfiler.txt  - File Missing', 'None', 'None','None', 'None'])
                NonC_DF = pd.DataFrame(share_info, columns=columns)


        elif vfiler == 'False':
            log_file = os.path.join(args[0], 'CIFS-SHARES.txt')
            try:
                with open(log_file) as file:
                    fo = file.read()
                    fo = fo + '\nendoffile'
                fo = fo[fo.index('---\n')+4 :]
                for j in CIFS_Share_comp.finditer(fo):
                    perm = re.sub('\t+', ' ', j.group(4))
                    perm = re.sub('[\n]+', ';', perm)
                    share_info.append([args[2], args[3], vfiler, j.group(1), j.group(2), j.group(3), perm])
                NonC_DF = pd.DataFrame(share_info, columns=columns)
            except Exception as e:
                share_info.append([args[2], args[3], 'CIFS-SHARES.vfiler.txt  - File Missing', 'None', 'None',
                                   'None', 'None'])
                NonC_DF = pd.DataFrame(share_info, columns=columns)
        Clus_DF = pd.DataFrame()
        return Clus_DF, NonC_DF


@counter_deco
def CIFS_Server(*args):
    if args[4] == 'true':
        NonC_DF = pd.DataFrame()
        all_values = []
        intr = ['vserver', 'name', 'domain_workgroup', 'domain', 'netbios_alias', 'admin_status']
        columns = ['Cluster_Name', 'Node_Name', 'VServer', 'CIFS_Server',
                   'Domain_Workgroup', 'Domain', 'Netbios_Alias', 'Admin_Status']
        try:
            root = ET.parse(Info_Map['CIFS_Server'][1])
            for i in root.findall('ASUP:ROW', nameservice):
                keys = ['CIFS_Server:' + str(text) for text in intr]
                values = [i.find(key, nameservice).text for key in keys]
                values.insert(0, args[3])
                values.insert(0, args[2])
                all_values.append(values)
            Clus_DF = pd.DataFrame(all_values, columns=columns)
        except Exception as e:
            all_values.append([args[2], args[3], os.path.split(Info_Map['CIFS_Server'][1])[1] + '-  File Missing',
                               'None', 'None', 'None', 'None', 'None'])
            Clus_DF = pd.DataFrame(all_values, columns=columns)
        return Clus_DF, NonC_DF

    elif args[4] == 'false':
        Clus_DF = pd.DataFrame()
        log_file = os.path.join(args[0], 'VFILERS.txt')
        with open(log_file) as file:
            fo = file.read()
        if re.search('Use of vfilers requires multistore licensed_feature option enabled',fo ):
            vfiler = 'False'
        else:
            vfiler = 'Defined'
        columns = ['Cluster', 'Node', 'vFiler', 'Status', 'NetBios', 'Domain','AllowedProto', 'PATHs', 'IPs']
        if vfiler == 'Defined':
            try:
                with open(log_file, 'r') as f:
                    fr_vfiler_file = f.readlines()
                    vfiler_details = []
                    # allowed_bucket = []
                    # path_bucket = []
                    # IP_bucket = []
                for num, line in enumerate(fr_vfiler_file):
                    if vf.match(line):
                        Allowed_proto = []
                        paths = []
                        IPs = []
                        filer_name, filer_status = vf.match(line).groups()
                        with open(os.path.join(args[0], 'CIFS-DOMAININFO.vfiler.txt')) as f:
                            fr_domain_file = f.read()
                        exp = '(?<={})\nNetBIOS Domain:\s+([\w&$-]+)\nWindows Domain Name:\s+([\w&$\.-]+)\n'.format(filer_name)
                        vf_domain_details =re.search(exp,fr_domain_file )
                        if vf_domain_details:
                            vf_netbios  = vf_domain_details.group(1)
                            vf_domain_name = vf_domain_details.group(2)

                        else:
                            vf_domain_name = vf_netbios = 'Null'

                    elif 'Allowed:' in line:
                        Allowed_proto.append(vf_allowed_proto_comp.search(line).group(1))
                    elif 'Path:' in line:
                        paths.append(vf_path_comp.search(line).group(1))
                    elif 'IP address:' in line:
                        IPs.append(vf_IPadd.search(line).group(1))
                    elif 'Protocols disallowed:' in line:

                        vfiler_details.append([args[2], args[3], filer_name, filer_status, vf_netbios, vf_domain_name,
                                               ', '.join(Allowed_proto), ', '.join(paths),', '.join(IPs)])
                NonC_DF = pd.DataFrame(vfiler_details, columns=columns)
                return Clus_DF, NonC_DF
            except Exception as e:
                print (e)
                vfiler_details = []
                vfiler_details.append([args[2], args[3], 'VFILERS.txt - File Missing', 'None', 'None',
                                       'None', 'None', 'None', 'None'])
                NonC_DF = pd.DataFrame(vfiler_details, columns=columns)
                return Clus_DF, NonC_DF
        elif vfiler == 'False':
            log_file = os.path.join(args[0], 'CIFS-DOMAININFO.txt')
            physical_details = []
            try:
                with open(log_file) as file:
                    fr_phy_dom = file.readlines()[:4]
                phy_netbios = re.split('\s+',fr_phy_dom[0] )[2]
                phy_domain = re.split('\s+',fr_phy_dom[1] )[3]
                physical_details.append( [args[2], args[3], 'Physical', 'NA', phy_netbios, phy_domain,
                                               'NA', 'NA','NA'] )
                NonC_DF = pd.DataFrame(physical_details, columns=columns)
                return Clus_DF, NonC_DF

            except Exception as e:
                physical_details = []
                physical_details.append([args[2], args[3], 'CIFS-DOMAININFO.txt - Read failed', 'None', 'None',
                                         'None', 'None', 'None', 'None'])
                NonC_DF = pd.DataFrame(physical_details, columns=columns)
                return Clus_DF, NonC_DF

@counter_deco
def DNS(*args):
    all_values = []
    if args[4] == 'true':
        intr = ['vserver', 'state']
        NonC_DF = pd.DataFrame()
        root = ET.parse(Info_Map['DNS'][1])
        for i in root.findall('ASUP:ROW', nameservice):
            keys = ['DNS:' + str(text) for text in intr]
            values = [i.find(key, nameservice).text for key in keys]
            key = 'DNS:'+ 'domains'
            domains = [ q.text for p in i.find(key, nameservice) for q in p]
            key = 'DNS:'+ 'nameservers'
            ns = [ q.text for p in i.find(key, nameservice) for q in p]
            values.extend([','.join(domains), ','.join(ns) ])
            values.insert(0, args[3])
            values.insert(0, args[2])
            all_values.append(values)
        columns = ['Cluster', 'Node', 'vServer', 'State', 'Domains', 'Nameservers']
        C_DF = pd.DataFrame(all_values, columns=columns)
        return C_DF, NonC_DF
    elif args[4] == 'false':
        NonC_DF = pd.DataFrame()
        C_DF = pd.DataFrame()
        log_file = os.path.join(args[0], 'DNS-info.txt')
        try:
            with open(log_file, 'r') as file:
                fo = file.read()
            dns = [[args[2], args[3], x[0], x[1] ] for x in dns_comp.findall(fo) ]
            dns.append([ args[2], args[3], 'Default Domain', re.search('Default domain:\s(.*)', fo).group(1) ])
            dns.append([ args[2], args[3], 'Search Domains', re.search('Search domains:\s(.*)', fo).group(1) ])
            NonC_DF = pd.DataFrame(dns, columns=['Cluster', 'Node', 'NameServers', 'State'] )
            return C_DF, NonC_DF
        except Exception as e:
            all_values.append([args[2], args[3], 'DNS-INFO.txt - file missing', 'None'])
            NonC_DF = pd.DataFrame(all_values, columns=['Cluster', 'Node', 'NameServers', 'State'] )
            return C_DF, NonC_DF

@counter_deco
def SNAP_Mirror(*args):
    all_values = []
    if args[4] == 'true' :
        intr = ['source_path', 'destination_path','source_volume_node']
        NonC_DF = pd.DataFrame()
        columns= ['Cluster_Name', 'Node_Name','source_path', 'destination_path','source_volume_node']
        try:
            root = ET.parse(Info_Map['SNAPMIRROR_DESTINATION'][1])
            for i in root.findall('ASUP:ROW', nameservice):
                keys = ['SNAPMIRROR_DESTINATION:' + str(text) for text in intr]
                values = [i.find(key, nameservice).text for key in keys]
                values.insert(0, args[3])
                values.insert(0, args[2])
                all_values.append(values)
            Clus_DF = pd.DataFrame(all_values, columns=columns)
        except Exception as e:
            all_values.append( [ args[2], args[3], os.path.split(Info_Map['SNAPMIRROR_DESTINATION'][1])[1] + ' - File missing',
                                'None', 'None' ])
            Clus_DF = pd.DataFrame(all_values, columns=columns)
        return Clus_DF, NonC_DF
    elif args[4] == 'false':
        C_DF = pd.DataFrame()
        intr = ['Node', 'Destination-node-name' ,'Destination-node-path' ,'Source-node-name' ,
                'Source-node-path' ,'Source-Snapshot']
        log_file = os.path.join(args[0], 'smDestinations.xml')
        try:
            root = ET.parse(log_file)
            for i in root.findall('ASUP:ROW', nameservice):
                keys = ['NonC_SNAPMIRROR_DESTINATION:' + str(text) for text in intr[1:]]
                values = [i.find(key, nameservice).text for key in keys]
                values.insert(0, args[3])
                values.insert(0, args[2])
                all_values.append(values)
            intr.insert(0, 'Cluster')
            NonC_DF = pd.DataFrame(all_values, columns=intr)
            return C_DF, NonC_DF
        except Exception as e:
            all_values.append([args[2], args[3], 'smDestinations.xml - File missing', 'None',
                              'None', 'None', 'None'])
            intr.insert(0, 'Cluster')
            NonC_DF = pd.DataFrame(all_values, columns=intr)
            return C_DF, NonC_DF

@counter_deco
def NTP(*args):
    log_file = os.path.join(args[0], 'var-etc-ntp-conf.txt')
    try:
        with open(log_file, 'r') as file:
            fo = file.read()
        result = ntp_comp.findall(fo)
        ntp_string = StringIO('\n'.join(result) )
        columns = ['Cluster', 'Server', 'Node', 'Version']
        ntp_pd  = pd.read_csv(ntp_string, sep='\s+', header=None, names=columns)
        ntp_pd = ntp_pd.assign(Cluster=args[2])
        ntp_pd = ntp_pd.assign(Node=args[3])
        columns = ['Cluster', 'Node', 'Server','Version']
        ntp_pd = ntp_pd[columns]
        C_DF = ntp_pd[ntp_pd.Cluster != 'None']
        NonC_DF = ntp_pd[ntp_pd.Cluster == 'None']
        return C_DF, NonC_DF
    except Exception as e:
        all_values = [[args[2], args[3],' var-etc-ntp-conf.txt -file Missing', 'None' ]]
        if args[4] == 'true':
            NonC_DF = pd.DataFrame()
            C_DF = pd.DataFrame(all_values, columns = ['Cluster', 'Node', 'Server','Version'] )
            return C_DF, NonC_DF
        elif args[4] == 'false':
            C_DF = pd.DataFrame()
            NonC_DF = pd.DataFrame(all_values, columns = ['Cluster', 'Node', 'Server','Version'] )
            return C_DF, NonC_DF


@counter_deco
def Mtree(*args):
    if args[4] == 'true':
        NonC_DF = pd.DataFrame()
        all_values = []
        intr = ['vs', 'vol', 'opl', 'qt', 'status', 'sec', 'exp']
        columns = ['Cluster_Name', 'Node_Name', 'VServer', 'VOL', 'Oplocks', 'Qtree_Name',
                   'Status', 'SecurityStyle', 'Export_Policy']

        try:
            root = ET.parse(Info_Map['QTREE'][1])
            for i in root.findall('ASUP:ROW', nameservice):
                keys = ['QTREE:' + str(text) for text in intr]
                values = [i.find(key, nameservice).text for key in keys]
                values.insert(0, args[3])
                values.insert(0, args[2])
                all_values.append(values)
            C_DF = pd.DataFrame(all_values, columns=columns)
            return C_DF, NonC_DF
        except Exception as e:
            all_values.append([args[2], args[3], 'qtree.xml - File missing', 'None',
                               'None', 'None', 'None', 'None', 'None'])
            C_DF = pd.DataFrame(all_values, columns=columns)
            return C_DF, NonC_DF

    elif args[4] == 'false':
        log_file = os.path.join(args[0], 'QTREE-STATUS.txt')
        all_values = []
        try:
            NonC_DF = pd.read_csv(log_file, sep='\s+', header=None)
            NonC_DF.columns = NonC_DF.loc[0]
            NonC_DF = NonC_DF[2:]
            #             DF_I = DF_I.rename(columns= {'iused': 'inodes_Used', 'ifree': 'inodes_Free'})
            NonC_DF = NonC_DF[~NonC_DF.Owning.isnull()]
            NonC_DF = NonC_DF.assign(Cluster=args[2])
            NonC_DF = NonC_DF.assign(Node=args[3])
            NonC_DF = NonC_DF.drop(labels='vfiler', axis=1)
            NonC_DF = NonC_DF.rename(columns={'Owning': 'Owning_vFiler'})
            columns = ['Cluster', 'Node', 'Volume', 'Tree', 'Style', 'Oplocks', 'Status', 'ID', 'Owning_vFiler']
            NonC_DF = NonC_DF[columns]
            C_DF = pd.DataFrame()
            return C_DF, NonC_DF
        except Exception as e:
            C_DF = pd.DataFrame()
            columns = ['Cluster', 'Node', 'Volume', 'Tree', 'Style', 'Oplocks', 'Status', 'ID', 'Owning_vFiler']
            all_values.append([args[2], args[3], 'QTREE-STATUS.txt - File Missing', 'None', 'None', 'None', 'None',
                               'None', 'None'])
            NonC_DF = pd.DataFrame(all_values, columns=columns)
            NonC_DF = NonC_DF[columns]
            return C_DF, NonC_DF


@counter_deco
def NetworkAdapers(*args):
    import pdb
    IP_config = []
    log_file = os.path.join(args[0], 'IFGRP-STATUS.txt')
    with open(log_file) as file:
        fo = file.read()
        fo = fo + 'end_of_string:'
    adapters = {}
    sub_adapters = {}
    for para in Net_para_comp.finditer(fo):
        matches = Net_Mediatype.findall(para.group(3))
        sub_ada = ''
        for sub in matches:
            sub_ada = ', '.join(sub) + '  ' + sub_ada
            sub_adapters[sub[0]] = ', '.join([sub[1], sub[2]])
        adapters[para.group(1)] = sub_ada
        for k, v in sub_adapters.items():
            if adapters.__contains__(k) is False:
                adapters[k] = v
                # adapters.update(sub_adapters)
    if args[4] == 'true':
        NonC_DF = pd.DataFrame()
        all_values = []
        intr = ['port', 'role', 'link', 'mtu', 'mac', 'type']
        root = ET.parse(Info_Map['NetPorts'][1])
        values = []
        for i in root.findall('ASUP:ROW', nameservice):
            keys = ['NetPorts:' + str(text) for text in intr]
            values = [i.find(key, nameservice).text for key in keys]
            values.insert(len(values), adapters.get(values[0], 'None'))
            values.insert(0, args[3])
            values.insert(0, args[2])
            all_values.append(values)
        columns = ['Cluster', 'Node', 'Port', 'Role', 'Link', 'MTU', 'MAC', 'Type', 'Sub_Adapters']
        Clus_DF = pd.DataFrame(all_values, columns=columns)
        return Clus_DF, NonC_DF
    elif args[4] == 'false':
        log_file = os.path.join(args[0], 'IFCONFIG-A.txt')
        with open(log_file, 'r') as file:
            fo = file.read()
        fo = fo + 'Endoffile: paras='
        IP_config = []
        columns = ['Cluster', 'Node', 'Adapter', 'MTU', 'MAC', 'IPs', 'vFiler', 'Sub-Adapters']
        IP_paras = IP_para_comp.finditer(fo)
        for para in IP_paras:
            ada_mru = ser_ada_mtu.search(para.group(1))
            eth = ser_ether.search(para.group(1))
            vf = ser_vf_ipconfig.findall(para.group(1))
            inet = ser_inet.findall(para.group(1))
            inet_list = list(map(lambda x, y: '/'.join([x, y]), [x[0] for x in inet], [x[1] for x in inet])) if len(
                inet) > 0 else 'Null'
            IP_config.append([args[2], args[3], ada_mru.group(1), ada_mru.group(2), eth.group(1) if eth else 'Null',
                              ', '.join(inet_list) if type(inet_list) == list else 'Null',
                              ', '.join(vf) if vf else 'Null',
                              adapters.get(ada_mru.group(1), 'None')])
        NonC_DF = pd.DataFrame(IP_config, columns=columns)
        Clus_DF = pd.DataFrame()

        return Clus_DF, NonC_DF


if __name__ == '__main__':
    (Name_locs, Names, Words, base, ASUP, files, path, pathplus, loc_7z, Info_Map, nameservice, no_files) = setup()
    int= utils()
    int.renew(pathplus)
    func = [exports, CIFS_Server, CIFS_Share]
    for file in files:
        print (file)
        int.renew(pathplus)
        full_file = os.path.join(path, file)
        cmd = loc_7z + ' e ' + full_file + ' -o' + pathplus
        int.command(cmd)
        log_file = os.path.join(pathplus, 'X-HEADER-DATA.TXT')
        All_Nodes_Summary = pd.DataFrame(Node_verbose(log_file))
        pos = All_Nodes_Summary.index.size-1
        Cluster, Node, Clustered_ =  All_Nodes_Summary.Cluster_Name.loc[pos], All_Nodes_Summary.Node.loc[pos], All_Nodes_Summary.Clustered_.loc[pos]
        Dummy, ALL_VOLs = get_volumes(pathplus, no_files, Cluster, Node, Clustered_)
        C_Exports, NonC_Exports = exports(pathplus, no_files, Cluster, Node, Clustered_)
        C_CIFS_Servers, NonC_CIFS_Servers = CIFS_Server(pathplus, no_files, Cluster, Node, Clustered_)
        C_CIFS_Share, NonC_CIFS_Share = CIFS_Share(pathplus, no_files, Cluster, Node, Clustered_)
        C_SNAP, Non_C_SNAP = SNAP_Mirror(pathplus, no_files, Cluster, Node, Clustered_)
        C_QTREE, Non_C_QTREE = Mtree(pathplus, no_files, Cluster, Node, Clustered_)
        C_DNS, NonC_DNS = DNS(pathplus, no_files, Cluster, Node, Clustered_)
        C_NTP, NonC_NTP = NTP(pathplus, no_files, Cluster, Node, Clustered_)
        C_ALL_Net, NonC_ALL_Net = NetworkAdapers(pathplus, no_files, Cluster, Node, Clustered_)


    C_Node_Summary = All_Nodes_Summary[All_Nodes_Summary.Cluster_Name != 'None']
    NonC_Node_Summary = All_Nodes_Summary[All_Nodes_Summary.Cluster_Name == 'None']
    C_ALL_VOLs = ALL_VOLs[ALL_VOLs.Cluster != 'None']
    NonC_ALL_VOLs = ALL_VOLs[ALL_VOLs.Cluster == 'None']

    C_writer = pd.ExcelWriter('Cluster.xlsx', engine='xlsxwriter')
    NC_writer = pd.ExcelWriter('NonCluster.xlsx', engine='xlsxwriter')

    C_Node_Summary.to_excel(C_writer, sheet_name='Cluster_Summary')
    C_ALL_VOLs.to_excel(C_writer, sheet_name='Cluster_Volumes')
    C_CIFS_Share.to_excel(C_writer, sheet_name='Cluster_CIFS_Shares')
    C_CIFS_Servers.to_excel(C_writer, sheet_name='Cluster_CIFS_Servers')
    C_Exports.to_excel(C_writer, sheet_name='Exports')
    C_SNAP.to_excel(C_writer, sheet_name='Cluster_SnapMirror')
    C_QTREE.to_excel(C_writer, sheet_name='Cluster_QTREE')
    C_NTP.to_excel(C_writer, sheet_name='Cluster_NTP')
    C_DNS.to_excel(C_writer, sheet_name='Cluster_DNS')
    C_ALL_Net.to_excel(C_writer, sheet_name='Cluster_Network')

    i = DV.addGraph( path)
    i.ClusterInfo(C_Node_Summary)
    i.shareInfo(C_ALL_VOLs, 'true')
    wb = C_writer.sheets['Cluster_Summary']
    wb.insert_image('P5', os.path.join(path, 'Cluster_Summary.png'))
    wb = C_writer.sheets['Cluster_Volumes']
    wb.insert_image('R5', os.path.join(path, 'Clus_Vol_Filesystems.png'))
    wb.insert_image('R80', os.path.join(path, 'Clus_Vol_Space.png'))

    NonC_Node_Summary.to_excel(NC_writer, sheet_name='NonCluster_Summary')
    NonC_ALL_VOLs.to_excel(NC_writer, sheet_name='NonCluster_Volumes')
    NonC_CIFS_Share.to_excel(NC_writer, sheet_name='NonCluster_CIFS_Shares')
    NonC_CIFS_Servers.to_excel(NC_writer, sheet_name='NonCluster_CIFS_Servers')
    NonC_Exports.to_excel(NC_writer, sheet_name='Exports')
    Non_C_SNAP.to_excel(NC_writer, sheet_name='NonCluster_SnapMirror')
    Non_C_QTREE.to_excel(NC_writer, sheet_name='NonCluster_QTREE')
    NonC_NTP.to_excel(NC_writer, sheet_name='NonCluster_NTP')
    NonC_DNS.to_excel(NC_writer, sheet_name='NonCluster_DNS')
    NonC_ALL_Net.to_excel(NC_writer, sheet_name='NonCluster_Networks')

    j = DV.addGraph(path)
    j.ClusterInfo(NonC_Node_Summary)
    j.shareInfo(NonC_ALL_VOLs, 'false')
    wb = NC_writer.sheets['NonCluster_Summary']
    wb.insert_image('R5', os.path.join(path, 'NonCluster_Summary.png'))
    wb =  NC_writer.sheets['NonCluster_Volumes']
    wb.insert_image('R5', os.path.join(path, 'NonClus_Vol_Filesystems.png'))
    wb.insert_image('R80', os.path.join(path, 'NonClus_VolSpace.png'))


    for writer in [NC_writer, C_writer]:
        workbook  = writer.book
        format = workbook.add_format()
        Green_font = workbook.add_format({'bg_color': '#F2D7D5',
                                   'font_color': '#212F3C', 'bold': False, })
        Green_font.set_align('center')
        Green_font.set_align('vcenter')
        Green_font.set_border()
        for sheets in workbook.worksheets():
            sheets.set_column('A:A', None, None, {'hidden': True})
            sheets.set_column('B:Z', 25, Green_font)
        writer.save()
        workbook.close()


