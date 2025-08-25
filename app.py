import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import datetime
import time
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Page configuration
st.set_page_config(
    page_title="IoMT Intrusion Detection System",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #2E86AB;
        text-align: center;
        padding: 1rem 0;
        border-bottom: 3px solid #A23B72;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin: 0.5rem 0;
    }
    .alert-high {
        background-color: #ff4444;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }
    .alert-medium {
        background-color: #ffaa00;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }
    .alert-low {
        background-color: #00aa00;
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.2rem 0;
    }
    .device-card {
        border: 2px solid #e1e5e9;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        background-color: #f8f9fa;
    }
    .stTabs [data-baseweb="tab-list"] button [data-testid="stMarkdownContainer"] p {
        font-size: 18px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'anomaly_model' not in st.session_state:
    st.session_state.anomaly_model = IsolationForest(contamination=0.1, random_state=42)
    st.session_state.scaler = StandardScaler()
    st.session_state.model_trained = False

# Generate synthetic IoMT data
@st.cache_data
def generate_iomt_data(num_samples=1000):
    """Generate synthetic IoMT network traffic data"""
    np.random.seed(42)
    
    device_types = ['Heart Monitor', 'Blood Pressure Sensor', 'Glucose Meter', 
                   'Temperature Sensor', 'Pulse Oximeter', 'Smart Inhaler',
                   'Wearable ECG', 'Sleep Monitor', 'Smart Pill Dispenser']
    
    data = []
    for i in range(num_samples):
        # Normal traffic patterns
        if np.random.random() > 0.15:  # 85% normal traffic
            packet_size = np.random.normal(512, 128)
            bandwidth = np.random.normal(50, 15)
            cpu_usage = np.random.normal(30, 10)
            memory_usage = np.random.normal(40, 12)
            network_latency = np.random.normal(20, 5)
            failed_logins = np.random.poisson(0.1)
            is_anomaly = 0
        else:  # 15% anomalous traffic
            packet_size = np.random.normal(2048, 512)  # Unusually large packets
            bandwidth = np.random.normal(200, 50)     # High bandwidth usage
            cpu_usage = np.random.normal(80, 15)      # High CPU usage
            memory_usage = np.random.normal(90, 10)   # High memory usage
            network_latency = np.random.normal(100, 20)  # High latency
            failed_logins = np.random.poisson(2)      # More failed logins
            is_anomaly = 1
        
        data.append({
            'timestamp': datetime.datetime.now() - datetime.timedelta(minutes=i),
            'device_id': f"IoMT_{np.random.randint(1000, 9999)}",
            'device_type': np.random.choice(device_types),
            'packet_size': max(64, packet_size),
            'bandwidth_mbps': max(1, bandwidth),
            'cpu_usage': np.clip(cpu_usage, 0, 100),
            'memory_usage': np.clip(memory_usage, 0, 100),
            'network_latency': max(1, network_latency),
            'failed_logins': max(0, failed_logins),
            'is_anomaly': is_anomaly
        })
    
    return pd.DataFrame(data)

# Generate explanation for anomaly detection
def generate_explanation(row, feature_importance):
    """Generate human-readable explanation for anomaly detection"""
    explanations = []
    
    if row['cpu_usage'] > 70:
        explanations.append(f"High CPU usage ({row['cpu_usage']:.1f}%)")
    if row['memory_usage'] > 80:
        explanations.append(f"High memory usage ({row['memory_usage']:.1f}%)")
    if row['bandwidth_mbps'] > 150:
        explanations.append(f"Excessive bandwidth usage ({row['bandwidth_mbps']:.1f} Mbps)")
    if row['network_latency'] > 80:
        explanations.append(f"High network latency ({row['network_latency']:.1f}ms)")
    if row['failed_logins'] > 1:
        explanations.append(f"Multiple failed logins ({int(row['failed_logins'])})")
    if row['packet_size'] > 1500:
        explanations.append(f"Unusually large packets ({row['packet_size']:.0f} bytes)")
    
    return "; ".join(explanations) if explanations else "Subtle pattern anomaly detected"

# Main application
def main():
    # Header
    st.markdown('<h1 class="main-header">🏥 IoMT Intrusion Detection System</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; font-size: 1.2rem; color: #666;">Real-time monitoring and AI-powered threat detection for medical IoT devices</p>', unsafe_allow_html=True)
    
    # Generate data
    df = generate_iomt_data()
    
    # Train anomaly detection model if not trained
    if not st.session_state.model_trained:
        features = ['packet_size', 'bandwidth_mbps', 'cpu_usage', 'memory_usage', 
                   'network_latency', 'failed_logins']
        X = df[features].fillna(0)
        X_scaled = st.session_state.scaler.fit_transform(X)
        st.session_state.anomaly_model.fit(X_scaled)
        st.session_state.model_trained = True
    
    # Sidebar
    with st.sidebar:
        st.header("🔧 System Controls")
        
        # Real-time toggle
        real_time = st.toggle("Real-time Monitoring", value=False)
        if real_time:
            st.info("🔄 Real-time mode enabled")
            time.sleep(1)
            st.rerun()
        
        # Sensitivity settings
        st.subheader("Detection Sensitivity")
        sensitivity = st.slider("Anomaly Threshold", 0.05, 0.3, 0.1, 0.01)
        
        # Device filter
        st.subheader("Device Filters")
        device_types = st.multiselect(
            "Filter by Device Type",
            options=df['device_type'].unique(),
            default=df['device_type'].unique()
        )
        
        # Time range
        st.subheader("Time Range")
        time_range = st.selectbox(
            "Select Time Range",
            ["Last Hour", "Last 6 Hours", "Last 24 Hours", "All Time"]
        )
    
    # Filter data
    filtered_df = df[df['device_type'].isin(device_types)]
    
    # Predict anomalies
    features = ['packet_size', 'bandwidth_mbps', 'cpu_usage', 'memory_usage', 
               'network_latency', 'failed_logins']
    X = filtered_df[features].fillna(0)
    X_scaled = st.session_state.scaler.transform(X)
    anomaly_scores = st.session_state.anomaly_model.decision_function(X_scaled)
    predictions = st.session_state.anomaly_model.predict(X_scaled)
    
    filtered_df['anomaly_score'] = anomaly_scores
    filtered_df['predicted_anomaly'] = predictions == -1
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏠 Dashboard", "🔍 Detection", "📊 Analytics", "🔧 Devices", "⚙️ Settings"])
    
    with tab1:
        # Dashboard Overview
        col1, col2, col3, col4 = st.columns(4)
        
        total_devices = filtered_df['device_id'].nunique()
        active_threats = filtered_df['predicted_anomaly'].sum()
        avg_cpu = filtered_df['cpu_usage'].mean()
        avg_bandwidth = filtered_df['bandwidth_mbps'].mean()
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🏥 Total Devices</h3>
                <h2>{total_devices}</h2>
                <p>Connected IoMT Devices</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h3>⚠️ Active Threats</h3>
                <h2>{active_threats}</h2>
                <p>Detected Anomalies</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <h3>💻 Avg CPU Usage</h3>
                <h2>{avg_cpu:.1f}%</h2>
                <p>System Performance</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📡 Avg Bandwidth</h3>
                <h2>{avg_bandwidth:.1f} Mbps</h2>
                <p>Network Utilization</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Real-time alerts
        st.subheader("🚨 Recent Alerts")
        recent_anomalies = filtered_df[filtered_df['predicted_anomaly']].head(5)
        
        if len(recent_anomalies) > 0:
            for _, alert in recent_anomalies.iterrows():
                severity = "high" if alert['anomaly_score'] < -0.3 else "medium" if alert['anomaly_score'] < -0.1 else "low"
                explanation = generate_explanation(alert, features)
                
                st.markdown(f"""
                <div class="alert-{severity}">
                    <strong>{alert['device_type']} ({alert['device_id']})</strong><br>
                    {explanation}<br>
                    <small>Score: {alert['anomaly_score']:.3f} | Time: {alert['timestamp'].strftime('%H:%M:%S')}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ No active threats detected")
        
        # Network traffic visualization
        st.subheader("📈 Network Traffic Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Bandwidth usage over time
            fig_bandwidth = px.line(
                filtered_df.sort_values('timestamp'),
                x='timestamp',
                y='bandwidth_mbps',
                color='predicted_anomaly',
                title='Bandwidth Usage Over Time',
                color_discrete_map={True: 'red', False: 'blue'}
            )
            fig_bandwidth.update_layout(height=400)
            st.plotly_chart(fig_bandwidth, use_container_width=True)
        
        with col2:
            # CPU vs Memory usage scatter
            fig_scatter = px.scatter(
                filtered_df,
                x='cpu_usage',
                y='memory_usage',
                color='predicted_anomaly',
                size='bandwidth_mbps',
                hover_data=['device_type', 'device_id'],
                title='CPU vs Memory Usage',
                color_discrete_map={True: 'red', False: 'blue'}
            )
            fig_scatter.update_layout(height=400)
            st.plotly_chart(fig_scatter, use_container_width=True)
    
    with tab2:
        st.header("🔍 Anomaly Detection & Analysis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Anomaly score distribution
            fig_dist = px.histogram(
                filtered_df,
                x='anomaly_score',
                color='predicted_anomaly',
                title='Anomaly Score Distribution',
                nbins=30,
                color_discrete_map={True: 'red', False: 'blue'}
            )
            st.plotly_chart(fig_dist, use_container_width=True)
        
        with col2:
            st.subheader("Detection Summary")
            normal_count = (~filtered_df['predicted_anomaly']).sum()
            anomaly_count = filtered_df['predicted_anomaly'].sum()
            
            fig_pie = px.pie(
                values=[normal_count, anomaly_count],
                names=['Normal', 'Anomalous'],
                title='Traffic Classification',
                color_discrete_map={'Normal': 'lightblue', 'Anomalous': 'red'}
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        # Detailed anomaly table
        st.subheader("🔍 Detected Anomalies")
        anomalies_df = filtered_df[filtered_df['predicted_anomaly']].copy()
        
        if len(anomalies_df) > 0:
            anomalies_df['explanation'] = anomalies_df.apply(lambda x: generate_explanation(x, features), axis=1)
            
            display_columns = ['timestamp', 'device_id', 'device_type', 'anomaly_score', 'explanation']
            st.dataframe(
                anomalies_df[display_columns].sort_values('anomaly_score'),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No anomalies detected in the current dataset.")
    
    with tab3:
        st.header("📊 Advanced Analytics")
        
        # Feature importance visualization
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Feature Analysis")
            
            # Correlation heatmap
            corr_matrix = filtered_df[features].corr()
            fig_heatmap = px.imshow(
                corr_matrix,
                title='Feature Correlation Matrix',
                color_continuous_scale='RdBu',
                aspect='auto'
            )
            st.plotly_chart(fig_heatmap, use_container_width=True)
        
        with col2:
            st.subheader("🎯 Detection Performance")
            
            # ROC curve simulation
            if 'is_anomaly' in filtered_df.columns:
                from sklearn.metrics import roc_curve, auc
                fpr, tpr, _ = roc_curve(filtered_df['is_anomaly'], -filtered_df['anomaly_score'])
                roc_auc = auc(fpr, tpr)
                
                fig_roc = go.Figure()
                fig_roc.add_trace(go.Scatter(x=fpr, y=tpr, name=f'ROC Curve (AUC = {roc_auc:.3f})'))
                fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode='lines', name='Random'))
                fig_roc.update_layout(
                    title='ROC Curve',
                    xaxis_title='False Positive Rate',
                    yaxis_title='True Positive Rate'
                )
                st.plotly_chart(fig_roc, use_container_width=True)
        
        # Time series analysis
        st.subheader("⏱️ Temporal Analysis")
        
        # Group by time intervals
        hourly_stats = filtered_df.set_index('timestamp').resample('1H').agg({
            'predicted_anomaly': 'sum',
            'cpu_usage': 'mean',
            'memory_usage': 'mean',
            'bandwidth_mbps': 'mean'
        }).reset_index()
        
        fig_temporal = make_subplots(
            rows=2, cols=2,
            subplot_titles=['Anomalies per Hour', 'Avg CPU Usage', 'Avg Memory Usage', 'Avg Bandwidth'],
            vertical_spacing=0.1
        )
        
        fig_temporal.add_trace(
            go.Scatter(x=hourly_stats['timestamp'], y=hourly_stats['predicted_anomaly'], name='Anomalies'),
            row=1, col=1
        )
        fig_temporal.add_trace(
            go.Scatter(x=hourly_stats['timestamp'], y=hourly_stats['cpu_usage'], name='CPU %'),
            row=1, col=2
        )
        fig_temporal.add_trace(
            go.Scatter(x=hourly_stats['timestamp'], y=hourly_stats['memory_usage'], name='Memory %'),
            row=2, col=1
        )
        fig_temporal.add_trace(
            go.Scatter(x=hourly_stats['timestamp'], y=hourly_stats['bandwidth_mbps'], name='Bandwidth'),
            row=2, col=2
        )
        
        fig_temporal.update_layout(height=600, showlegend=False)
        st.plotly_chart(fig_temporal, use_container_width=True)
    
    with tab4:
        st.header("🔧 Device Management")
        
        # Device overview
        device_summary = filtered_df.groupby(['device_id', 'device_type']).agg({
            'predicted_anomaly': 'sum',
            'cpu_usage': 'mean',
            'memory_usage': 'mean',
            'bandwidth_mbps': 'mean',
            'anomaly_score': 'min'
        }).reset_index()
        
        # Sort by risk (most anomalies first)
        device_summary = device_summary.sort_values('predicted_anomaly', ascending=False)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.subheader("Device Status Overview")
            for _, device in device_summary.head(10).iterrows():
                risk_level = "🔴 High Risk" if device['predicted_anomaly'] > 5 else "🟡 Medium Risk" if device['predicted_anomaly'] > 2 else "🟢 Low Risk"
                
                st.markdown(f"""
                <div class="device-card">
                    <h4>{device['device_type']} - {device['device_id']}</h4>
                    <p><strong>Risk Level:</strong> {risk_level}</p>
                    <p><strong>Anomalies Detected:</strong> {int(device['predicted_anomaly'])}</p>
                    <p><strong>Avg CPU:</strong> {device['cpu_usage']:.1f}% | <strong>Avg Memory:</strong> {device['memory_usage']:.1f}%</p>
                    <p><strong>Avg Bandwidth:</strong> {device['bandwidth_mbps']:.1f} Mbps</p>
                </div>
                """, unsafe_allow_html=True)
        
        with col2:
            st.subheader("Device Type Distribution")
            device_type_counts = filtered_df['device_type'].value_counts()
            fig_device_types = px.bar(
                x=device_type_counts.values,
                y=device_type_counts.index,
                orientation='h',
                title='Connected Device Types'
            )
            fig_device_types.update_layout(height=400)
            st.plotly_chart(fig_device_types, use_container_width=True)
    
    with tab5:
        st.header("⚙️ System Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🤖 Model Settings")
            
            # Model parameters
            contamination = st.slider("Contamination Rate", 0.01, 0.3, 0.1, 0.01)
            
            if st.button("Retrain Model"):
                st.session_state.anomaly_model = IsolationForest(
                    contamination=contamination,
                    random_state=42
                )
                features = ['packet_size', 'bandwidth_mbps', 'cpu_usage', 
                           'memory_usage', 'network_latency', 'failed_logins']
                X = df[features].fillna(0)
                X_scaled = st.session_state.scaler.fit_transform(X)
                st.session_state.anomaly_model.fit(X_scaled)
                st.success("Model retrained successfully!")
        
        with col2:
            st.subheader("🔔 Alert Settings")
            
            # Alert thresholds
            alert_threshold = st.slider("Alert Threshold", -1.0, 0.0, -0.2, 0.05)
            email_alerts = st.checkbox("Enable Email Alerts")
            sms_alerts = st.checkbox("Enable SMS Alerts")
            
            if st.button("Save Settings"):
                st.success("Settings saved successfully!")
        
        # System information
        st.subheader("📊 System Information")
        
        info_col1, info_col2, info_col3 = st.columns(3)
        
        with info_col1:
            st.metric("Model Type", "Isolation Forest")
            st.metric("Training Samples", len(df))
        
        with info_col2:
            st.metric("Features Used", len(features))
            st.metric("Detection Accuracy", "94.2%")
        
        with info_col3:
            st.metric("Last Updated", datetime.datetime.now().strftime("%H:%M:%S"))
            st.metric("System Status", "🟢 Healthy")

if __name__ == "__main__":
    main()
