import pandas as pd
import chardet
from sklearn.preprocessing import MinMaxScaler


     ############# READ THE FILE AND DETECT THE ENCODING ##########################
     
     
# detect the encoding of the csv file
with open('/Users/vel/Documents/datascienceNetworkingProject/general_packet_data.csv', 'rb') as file:
    result = chardet.detect(file.read(10000000)) # reading 10MB of data to detect the encoding
encoding = result['encoding']
with open('/Users/vel/Documents/datascienceNetworkingProject/http_data.csv', 'rb') as file:
    result = chardet.detect(file.read(10000000)) # reading 10MB of data to detect the encoding
encoding = result['encoding']

# read the csv file with the detected encoding
df_packets = pd.read_csv('/Users/vel/Documents/datascienceNetworkingProject/general_packet_data.csv', encoding=encoding)
df_http = pd.read_csv('/Users/vel/Documents/datascienceNetworkingProject/http_data.csv', encoding=encoding)


############# DATA CLEANING ##########################


# Remove duplicates based on all columns
df_packets = df_packets.drop_duplicates()
df_http = df_http.drop_duplicates()

# If you want to remove duplicates based on specific columns, you can specify them
df_http = df_http.drop_duplicates(subset=['timestamp'])

#Handling missing values -- drop rows with any missing values
#df_packets.dropna(inplace=True)
#df_http.dropna(inplace=True)

# Or fill missing values with a default value, e.g., 'Unknown' or 0
df_http.fillna({'http_method': 'Unknown', 'http_user_agent': 'Unknown'}, inplace=True)
df_packets.fillna({'source_ip': 'Unknown', 'destination_ip': 'Unknown', 'protocol': 'Unknown', 'tcp_flags': 'Unknown', 'payload_length': 'Unknown', 'dns_query': 'Unknown', 'dns_response': 'Unknown', 'mac_source': 'Unknown', 'mac_destination': 'Unknown', 'length': 'Unknown'}, inplace=True)

#Normalizing 'length' in df_packets
#convert 'length' to integer
df_packets['Length'] = pd.to_numeric(df_packets['length'], errors='coerce').astype('Int64')

# Fill NaN with a value, such as the mean or median of the column
df_packets['length'].fillna(df_packets['length'].mean(), inplace=True)

scaler = MinMaxScaler()
df_packets['length_normalized'] = scaler.fit_transform(df_packets[['length']])

#convert timestamps to datetime format
df_packets['timestamp'] = pd.to_datetime(df_packets['timestamp'], unit='s')
df_http['timestamp'] = pd.to_datetime(df_http['timestamp'], unit='s')

# extract specific time components, like hour of the day, for further analysis
df_packets['hour'] = df_packets['timestamp'].dt.hour
df_http['hour'] = df_http['timestamp'].dt.hour


############# FEATURE ENGINEERING ##########################



# Extract protocol type from protocol number

# AGGREGATE TRAFFIC BY HOUR ---------------------------------------------------------------------------------to get traffic volume
hourly_traffic = df_packets.groupby('hour').size().reset_index(name='traffic_volume')


# PROTOCOL FREQUENCY ----------------------------------------------------------------------------------------------

top_protocols = df_packets['protocol'].value_counts().nlargest(5).index.tolist()

# Create binary flags for the presence of these protocols
for protocol in top_protocols:
    df_packets[f'protocol_{protocol}'] = df_packets['protocol'].apply(lambda x: 1 if x == protocol else 0)
 
    
#### Repeated Connections !! ---------------------------------------------------------------------------

# Create a combined source-destination IP column
df_packets['src_destination_combo'] = df_packets['source_ip'] + '_' + df_packets['destination_ip']

#Count ocurances of each source-destination combo
df_packets['repeated_connections'] = df_packets.groupby('src_destination_combo')['src_destination_combo'].transform('count')


# MARK PACKETS AS ENCRYPTED based on destination port -------------------------------------------------------------
encrypted_ports = [443, 993, 995, 22, 990, 989, 465, 500/4500, 1194, 3389, 853, 8883, 636, 21]  # Example ports for HTTPS, IMAPS, POP3S, SSH
df_packets['is_encrypted'] = df_packets['dst_port'].apply(lambda x: 1 if x in encrypted_ports else 0)

# Compute standard deviation of packet lengths within a session
##df_packets['packet_length_std'] = df_packets.groupby(['src_ip', 'dst_ip', 'protocol'])['length'].transform('std')
##df_packets['likely_encrypted'] = df_packets['packet_length_std'].apply(lambda x: 1 if x is not None and x < threshold else 0)


# SESSION DURATION ----------------------------------------------------------------------------------------------

df_packets.sort_values(by=['source_ip','destination_ip', 'src_port', 'dst_port', 'timestamp'], inplace=True)

#calculate differences in consecutive packet timestamps within each session
df_packets['time_diff'] = df_packets.groupby(['source_ip', 'destination_ip', 'src_port', 'dst_port'])['timestamp'].diff()

#sum the time differences to get session durations
df_packets['session_duration'] = df_packets.groupby(['source_ip', 'destination_ip', 'src_port', 'dst_port'])['time_diff'].transform('sum')


# INTER-ARRIVAL TIMES ---------------------------------------------------------------------------------------

#calculate inter-arrival times directly
df_packets['inter_arrival_time'] = df_packets.groupby(['source_ip', 'destination_ip', 'src_port', 'dst_port'])['timestamp'].diff()


#BYTE AND PACKET COUNTS PER SESSSION --------------------------------------------------------------------

#Group by session and calculate total packet and byte counts ## Needs work??????????
session_stats = df_packets.groupby(['source_ip', 'destination_ip', 'src_port', 'dst_port']).agg(
    total_packets=('length', 'count'),
    total_bytes=('length', 'sum'),
    total_inter_arrival_time=('inter_arrival_time', 'sum')
).reset_index()
# Merge these stats back into the main DataFrame if needed
df_packets = df_packets.merge(session_stats, on=['source_ip', 'destination_ip', 'src_port', 'dst_port'], how='left')

# FLAG FREQUENCIES ------------------------------------------------------------------------------------------

# need to convert protocol into string for this to work

# NETWORK CONVERSATIONS AND NODE DEGREES --------------------------------------------## MAy need work

#Calculate the count of unique connections each IP adress is involved in 
df_packets['source_degree'] = df_packets.groupby('source_ip')['destination_ip'].transform('nunique')
df_packets['destination_degree'] = df_packets.groupby('destination_ip')['source_ip'].transform('nunique')

############# EXPORT DATA ##########################

df_packets.to_csv('cleaned_packets_data.csv', index=False)
df_http.to_csv('cleaned_http_data.csv', index=False)
