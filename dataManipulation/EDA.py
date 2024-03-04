import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx

#load dataset packets
df_packets = pd.read_csv('cleaned_packets_data.csv')

# load dataset http
df_http = pd.read_csv('cleaned_http_data.csv')

#basic summary statistics
print(df_packets.describe())

# Distribution of packet lengths
plt.figure(figsize=(10, 6))
sns.histplot(df_packets['length'], bins=30, kde=True)
plt.title('Distribution of Packet Lengths')
plt.xlabel('Packet Length')
plt.ylabel('Frequency')
plt.show()

# Count of packets by protocol
plt.figure(figsize=(10, 6))  # Adjust the figure size
sns.countplot(data=df_packets, x='protocol') 
plt.title('Packet Count by Protocol')
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.show()

# Traffic volume over time
df_packets['timestamp'] = pd.to_datetime(df_packets['timestamp'])
df_packets.set_index('timestamp', inplace=True)
df_packets.resample('h').size().plot()
plt.title('Traffic Volume Over Time (Hourly)')
plt.xlabel('Time') # This x-axis label does not seem to show any changes
plt.ylabel('Number of Packets')
plt.show()

###### HTTP EDA ################

# basic summaary statistics for HTTP data
print(df_http.describe())

# distribution of HTTP requests methods
plt.figure(figsize=(10, 6))
sns.countplot(data=df_http, x='http_method')
plt.title('Distribution of HTTP Request Methods')
plt.xlabel('HTTP Method')
plt.ylabel('Frequency')
plt.show()

# top requested hosts
top_hosts = df_http['http_host'].value_counts().nlargest(20)
plt.figure(figsize=(10, 6))
sns.barplot(x=top_hosts.index, y=top_hosts.values)
plt.title('Top 20 Requested Hosts')
plt.xlabel('Host')
plt.ylabel('Number of Requests')
plt.show()

# user-agent analysis (top-user agents)
top_user_agents = df_http['http_user_agent'].value_counts().nlargest(10)
plt.figure(figsize=(10, 6))
sns.barplot(x=top_user_agents.values, y=top_user_agents.index)
plt.title('Top HTTP User-Agents')
plt.xlabel('Frequency')
plt.ylabel('User-Agent')
plt.show()

# SESSION DURATION DISTRIBUTION ------------------------------------------------------------------------------

# Assuming 'session_duration' is in seconds
plt.figure(figsize=(10, 6))
# Remove NaN values
sns.histplot(df_packets['session_duration'].dropna(), bins=50, kde=True, log_scale=(True, False))
plt.title('Distribution of Session Durations (log scale)')
plt.xlabel('Session Duration (seconds)')
plt.ylabel('Frequency')
plt.show()

# INTER-ARRIVAL TIME DISTRIBUTION ----------------------------------------------------------------------------

# Can illustrate the regularity or 'burstiness' of traffic. A highly variable inter-arrival time might indicate irregular traffic patterns
plt.figure(figsize=(10, 6))
sns.histplot(df_packets['inter_arrival_time'], bins=50, kde=True, log_scale=(True, False))
plt.title('Distribution of Inter-Arrival Times (log scale)')
plt.xlabel('Inter-Arrival Time (seconds)')
plt.ylabel('Frequency')
plt.show()

# TRAFFIC VOLUME OVER TIME

# TOP PROTOCOLS BY PACKET COUNT ---------------------------------------------------------------------------

# Replace protocol numbers with names if known, for readability
protocol_names = {6: 'TCP', 17: 'UDP'}  # Example mapping
df_packets['protocol_name'] = df_packets['protocol'].map(protocol_names).fillna('Other')

plt.figure(figsize=(10, 6))
sns.countplot(data=df_packets, y='protocol_name', order = df_packets['protocol_name'].value_counts().index)
plt.title('Top Protocols by Packet Count')
plt.xlabel('Count')
plt.ylabel('Protocol')
plt.show()


# NETWORK CONVERSATIONS HEATMAP ---------------------------------------------------------------------------

# Count packets between each pair of source and destination IPs
conversation_counts = df_packets.groupby(['source_ip', 'destination_ip']).size().reset_index(name='counts')

# Pivot for heatmap; note: this might require sampling or focusing on top conversations if the dataset is large
pivot_table = conversation_counts.pivot(index="source_ip", columns="destination_ip", values="counts")
plt.figure(figsize=(12, 10))
sns.heatmap(pivot_table, cmap="YlGnBu")
plt.title('Heatmap of Network Conversations')
plt.xlabel('Destination IP')
plt.ylabel('Source IP')
plt.show()

# NETWORK GRAPH WITH EMPHASIS ON ENCRYPTION -----------------------------------------------------------------------

# Initialize a directed graph
G = nx.DiGraph()

# Add nodes and edges
for idx, row in df_packets.iterrows():
    # Add nodes for source and destination IPs if they don't already exist
    G.add_node(row['source_ip'], type='source')
    G.add_node(row['destination_ip'], type='destination')
    
    # Add an edge with the encryption status as an attribute
    G.add_edge(row['destination_ip'], row['destination_ip'], encryption=row['is_encrypted'])
    
# Node sizes and colors (blue for sources and pink for destinations)
node_sizes = [G.degree(n) * 100 for n in G.nodes]
node_colors = ['skyblue' if G.nodes[n]['type'] == 'source' else 'pink' for n in G.nodes]

# Edge colors based on encryption status
edge_colors = ['red' if G[u][v]['encryption'] == 1 else 'black' for u, v in G.edges()]

# Draw the network
plt.figure(figsize=(12,8))
pos = nx.spring_layout(G) # positions for all nodes
nx.draw_networkx_nodes(G, pos, node_size=node_sizes, node_color=node_colors, alpha=0.8)
nx.draw_networkx_edges(G, pos, edge_color=edge_colors, arrowstyle='->', arrowsize=10)
nx.draw_networkx_labels(G, pos, font_size=8)
plt.title('Network Traffic Graph (Red Edges Indicate Encrypted Traffic)')
plt.axis('off') # remove the axis
plt.show()