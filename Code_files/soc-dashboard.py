import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import time
import pytz
from soar_integration import SOAREngine
from alert_simulator import AlertSimulator
from wazuh_integration import WazuhIntegration
from rule_engine import calculate_priority
from alert_database import AlertDatabase
from ip_geolocation import IPGeolocation
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# Page config
st.set_page_config(
    page_title="SOC Alert Triage System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# PROFESSIONAL DARK THEME CSS
st.markdown("""
<style>
.stApp { background-color: #0f172a !important; }
.main { background-color: #0f172a !important; }
h1 { color: #f1f5f9 !important; font-size: 1.8rem !important; font-weight: 700 !important; margin-bottom: 0.3rem !important; }
h2, h3, h4 { color: #f1f5f9 !important; }
p, .stMarkdown { color: #cbd5e1 !important; }
[data-testid="stMetricValue"] { font-size: 2.2rem !important; font-weight: 700 !important; color: #ffffff !important; }
[data-testid="stMetricLabel"] { color: #94a3b8 !important; font-size: 0.9rem !important; font-weight: 500 !important; }
.stMetric { background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important; padding: 1.5rem !important; border-radius: 12px !important; border: 1px solid #334155 !important; box-shadow: 0 4px 16px rgba(0,0,0,0.4) !important; }
.stButton > button { background-color: #3b82f6 !important; color: white !important; font-weight: 600 !important; border-radius: 8px !important; border: none !important; padding: 0.6rem 1.2rem !important; box-shadow: 0 4px 12px rgba(59,130,246,0.3) !important; }
.stButton > button:hover { background-color: #2563eb !important; box-shadow: 0 6px 20px rgba(59,130,246,0.5) !important; }
section[data-testid="stSidebar"] { background-color: #1e293b !important; border-right: 1px solid #334155 !important; }
section[data-testid="stSidebar"] h1, section[data-testid="stSidebar"] h2, section[data-testid="stSidebar"] h3 { color: #f1f5f9 !important; }
section[data-testid="stSidebar"] label { color: #cbd5e1 !important; }
.stDataFrame { background-color: #1e293b !important; border-radius: 12px !important; border: 1px solid #334155 !important; }
hr { border-color: #334155 !important; margin: 1rem 0 !important; }
.stTextInput input, .stTextArea textarea, .stSelectbox select { background-color: #1e293b !important; color: #e2e8f0 !important; border: 1px solid #334155 !important; border-radius: 6px !important; }
.stMultiSelect [data-baseweb="tag"] { background-color: #3b82f6 !important; }
.streamlit-expanderHeader { background-color: #1e293b !important; border: 1px solid #334155 !important; border-radius: 8px !important; color: #e2e8f0 !important; }
.stAlert { background-color: #1e293b !important; border: 1px solid #334155 !important; border-radius: 8px !important; color: #e2e8f0 !important; }
</style>
""", unsafe_allow_html=True)

# Initialize
if 'db' not in st.session_state:
    st.session_state.db = AlertDatabase()
    st.session_state.simulator = AlertSimulator()
    st.session_state.wazuh = WazuhIntegration()
    st.session_state.geo = IPGeolocation()
    st.session_state.alert_counter = st.session_state.db.get_alert_count() + 1
    st.session_state.investigations = {}
    st.session_state.current_page = "Dashboard"
if 'soar' not in st.session_state:
    st.session_state.soar = SOAREngine()

# PROFESSIONAL SOC REPORT GENERATOR
def generate_soc_report(filtered_df, stats_geo):
    """Generate professional SOC report PDF"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#1e3a8a'), spaceAfter=30, alignment=TA_CENTER, fontName='Helvetica-Bold')
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor('#1e40af'), spaceAfter=12, spaceBefore=12, fontName='Helvetica-Bold')
    normal_style = styles["BodyText"]
    
    elements.append(Paragraph("SECURITY OPERATIONS CENTER", title_style))
    elements.append(Paragraph("Threat Intelligence & Alert Analysis Report", styles['Heading2']))
    elements.append(Spacer(1, 12))
    
    report_time = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
    elements.append(Paragraph(f"<b>Report Generated:</b> {report_time}", normal_style))
    elements.append(Paragraph(f"<b>Report Period:</b> {datetime.now().strftime('%Y-%m-%d')}", normal_style))
    elements.append(Paragraph(f"<b>Total Alerts Analyzed:</b> {len(filtered_df)}", normal_style))
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    
    critical_count = len(filtered_df[filtered_df['priority'] == 'CRITICAL'])
    high_count = len(filtered_df[filtered_df['priority'] == 'HIGH'])
    medium_count = len(filtered_df[filtered_df['priority'] == 'MEDIUM'])
    low_count = len(filtered_df[filtered_df['priority'] == 'LOW'])
    
    summary_text = f"""This report provides a comprehensive analysis of security alerts detected by the SOC Alert Triage System. During the reporting period, a total of <b>{len(filtered_df)} security alerts</b> were analyzed and prioritized using AI-driven rule-based algorithms.<br/><br/><b>Alert Distribution:</b><br/>• Critical Priority: {critical_count} alerts ({(critical_count/len(filtered_df)*100):.1f}%)<br/>• High Priority: {high_count} alerts ({(high_count/len(filtered_df)*100):.1f}%)<br/>• Medium Priority: {medium_count} alerts ({(medium_count/len(filtered_df)*100):.1f}%)<br/>• Low Priority: {low_count} alerts ({(low_count/len(filtered_df)*100):.1f}%)"""
    elements.append(Paragraph(summary_text, normal_style))
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("ALERT PRIORITY BREAKDOWN", heading_style))
    priority_data = [['Priority Level', 'Count', 'Percentage', 'Status'], ['Critical', str(critical_count), f"{(critical_count/len(filtered_df)*100):.1f}%", 'Immediate Action'], ['High', str(high_count), f"{(high_count/len(filtered_df)*100):.1f}%", 'Urgent Review'], ['Medium', str(medium_count), f"{(medium_count/len(filtered_df)*100):.1f}%", 'Scheduled Investigation'], ['Low', str(low_count), f"{(low_count/len(filtered_df)*100):.1f}%", 'Monitoring']]
    
    priority_table = Table(priority_data, colWidths=[2*inch, 1*inch, 1.5*inch, 2*inch])
    priority_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke), ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('FONTSIZE', (0, 0), (-1, 0), 12), ('BOTTOMPADDING', (0, 0), (-1, 0), 12), ('BACKGROUND', (0, 1), (-1, -1), colors.beige), ('GRID', (0, 0), (-1, -1), 1, colors.black), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])]))
    elements.append(priority_table)
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("THREAT INTELLIGENCE", heading_style))
    threat_counts = filtered_df['threat_type'].value_counts().head(5)
    threat_text = "<b>Top 5 Threat Categories:</b><br/><br/>"
    for idx, (threat, count) in enumerate(threat_counts.items(), 1):
        threat_name = threat.replace('_', ' ').title()
        threat_text += f"{idx}. {threat_name}: {count} incidents<br/>"
    elements.append(Paragraph(threat_text, normal_style))
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("GEOGRAPHIC THREAT ORIGINS", heading_style))
    geo_data = [['Rank', 'Country', 'Total', 'Critical', 'High']]
    for idx, (country, data) in enumerate(sorted(stats_geo.items(), key=lambda x: x[1]['count'], reverse=True)[:10], 1):
        geo_data.append([str(idx), country, str(data['count']), str(data['critical']), str(data['high'])])
    
    geo_table = Table(geo_data, colWidths=[0.8*inch, 2*inch, 1.5*inch, 1*inch, 1*inch])
    geo_table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a8a')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke), ('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'), ('GRID', (0, 0), (-1, -1), 1, colors.black), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])]))
    elements.append(geo_table)
    elements.append(Spacer(1, 20))
    
    elements.append(PageBreak())
    elements.append(Paragraph("CRITICAL ALERTS DETAIL", heading_style))
    critical_alerts = filtered_df[filtered_df['priority'] == 'CRITICAL'].head(10)
    
    if not critical_alerts.empty:
        for idx, alert in critical_alerts.iterrows():
            alert_detail = f"""<b>Alert #{idx + 1}</b><br/><b>Time:</b> {alert['timestamp']}<br/><b>Source IP:</b> {alert['source_ip']}<br/><b>Threat:</b> {alert['threat_type'].replace('_', ' ').title()}<br/><b>Description:</b> {alert['description']}<br/><b>Score:</b> {alert['priority_score']}<br/>"""
            elements.append(Paragraph(alert_detail, normal_style))
            elements.append(Spacer(1, 10))
    else:
        elements.append(Paragraph("No critical alerts detected.", normal_style))
    
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("SECURITY RECOMMENDATIONS", heading_style))
    recommendations = """<b>Recommended Actions:</b><br/><br/>1. <b>Immediate:</b> Investigate all critical alerts<br/>2. <b>Geographic Blocking:</b> Implement controls for high-risk countries<br/>3. <b>Enhanced Monitoring:</b> Focus on top threat categories<br/>4. <b>Incident Response:</b> Activate procedures for critical threats<br/>5. <b>Policy Review:</b> Update security policies<br/>6. <b>Training:</b> Conduct security awareness sessions<br/>"""
    elements.append(Paragraph(recommendations, normal_style))
    
    footer_text = f"""<br/><br/>_______________________________________________________________________________<br/><b>Classification:</b> CONFIDENTIAL<br/><b>Generated by:</b> SOC Alert Triage System v2.0<br/><b>Report ID:</b> SOC-{datetime.now().strftime('%Y%m%d-%H%M%S')}<br/>"""
    elements.append(Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey)))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

# SIDEBAR
with st.sidebar:
    st.title("🛡️ SOC Platform")
    st.markdown("---")
    
    st.subheader("📋 Navigation")
    menu_options = {"🏠 Dashboard": "Dashboard", "🚨 Alerts": "Alerts", "🔍 Investigations": "Investigations", "📊 Analytics": "Analytics", "🗺️ Threat Map": "Threat Map","🤖 SOAR": "SOAR", "⚙️ Settings": "Settings"}
    selected_page = st.radio("", list(menu_options.keys()), label_visibility="collapsed")
    st.session_state.current_page = menu_options[selected_page]
    
    st.markdown("---")
    st.subheader("🔍 Filters")
    
    date_range = st.selectbox("Date Range", ["Today", "Last 7 Days", "Last 30 Days", "All Time"])
    priority_filter = st.multiselect("Priority", ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
    severity_filter = st.multiselect("Severity", ['critical', 'high', 'medium', 'low'], default=['critical', 'high', 'medium', 'low'])
    threat_filter = st.multiselect("Threat Type", ['brute_force', 'malware', 'ransomware', 'suspicious_activity', 'policy_violation', 'dos_attack'], default=['brute_force', 'malware', 'ransomware', 'suspicious_activity', 'policy_violation', 'dos_attack'])
    
    st.markdown("---")
    st.subheader("📡 Data Source")
    alert_source = st.radio("Source", ["🔴 Real Wazuh", "🔵 Simulated", "🟣 Both"])
    
    if st.button("🔄 Fetch Alerts", use_container_width=True):
        with st.spinner("Fetching alerts..."):
            if "Real" in alert_source or "Both" in alert_source:
                new_alerts = st.session_state.wazuh.get_recent_alerts(1000)
                saved_count = 0
                soar_executed = []
    
                for alert in new_alerts:
                    result = calculate_priority(alert)
                    alert['priority_score'] = result['score']
                    alert['priority'] = result['priority']
                    alert['triage_reasons'] = result['reasons']
                    alert['seq_id'] = st.session_state.alert_counter
                    st.session_state.alert_counter += 1
                    if st.session_state.db.save_alert(alert):
                        saved_count += 1
                        
                        soar_result = st.session_state.soar.execute_playbook(alert)
                        if soar_result:
                            soar_executions.append(soar_result)
                        

                if saved_count > 0:
                    st.success(f"✅ Fetched {saved_count} new alerts")

                    if soar_executions:
                        st.success(f"🤖 SOAR: Executed {len(soar_executions)} automated responses")

                        for exec_result in soar_executions:
                            with st.expander(f"🎯 {exec_result['playbook_name']} - {len(exec_result['actions'])} actions"):
                                for action in exec_result['actions']:
                                    if action['status'] == 'success':
                                        st.success(f"✅ Step {action['step']}: {action['action']} - {action.get('message', 'Success')}")
                                    else:
                                        st.error(f"❌ Step {action['step']}: {action['action']} - {action.get('error', 'Failed')}")
                else:
                    st.info(f"ℹ️ Retrieved {len(new_alerts)} alerts (no new)")
            
            if "Simulated" in alert_source or "Both" in alert_source:
                sim_alert = st.session_state.simulator.generate_alert()
                result = calculate_priority(sim_alert)
                sim_alert['priority_score'] = result['score']
                sim_alert['priority'] = result['priority']
                sim_alert['triage_reasons'] = result['reasons']
                sim_alert['source'] = 'simulated'
                sim_alert['seq_id'] = st.session_state.alert_counter
                st.session_state.alert_counter += 1
                st.session_state.db.save_alert(sim_alert)
                soar_result = st.session_state.soar.execute_playbook(sim_alert)
                if soar_result:
                    st.success(f"🤖 SOAR executed for simulated alert")

        st.rerun()
    
    st.markdown("---")
    stats = st.session_state.db.get_stats()
    st.metric("📊 Total", stats['total'])
    
    if st.button("🗑️ Clear DB", use_container_width=True):
        if st.checkbox("⚠️ Confirm deletion"):
            st.session_state.db.clear_all_alerts()
            st.session_state.alert_counter = 1
            st.session_state.investigations = {}
            st.success("✅ Cleared!")
            st.rerun()

# DATE FILTERING
if date_range == "Today":
    all_alerts = st.session_state.db.get_all_alerts()
    today = datetime.now().date()
    alerts = []
    for alert in all_alerts:
        try:
            ts_str = alert['timestamp']
            for suffix in ['Z', '+00:00', '.000Z', '.000+00:00']:
                ts_str = ts_str.replace(suffix, '')
            if 'T' in ts_str:
                alert_datetime = datetime.fromisoformat(ts_str)
            else:
                alert_datetime = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
            alert_date = alert_datetime.date()
            if alert_date == today:
                alerts.append(alert)
        except:
            alerts.append(alert)
elif date_range == "Last 7 Days":
    start = (datetime.now() - timedelta(days=7)).isoformat()
    end = datetime.now().isoformat()
    alerts = st.session_state.db.get_alerts_by_date_range(start, end)
elif date_range == "Last 30 Days":
    start = (datetime.now() - timedelta(days=30)).isoformat()
    end = datetime.now().isoformat()
    alerts = st.session_state.db.get_alerts_by_date_range(start, end)
else:
    alerts = st.session_state.db.get_all_alerts()

df = pd.DataFrame(alerts)
filtered_df = df[(df['priority'].isin(priority_filter)) & (df['severity'].isin(severity_filter)) & (df['threat_type'].isin(threat_filter))] if not df.empty else pd.DataFrame()

# DASHBOARD PAGE
if st.session_state.current_page == "Dashboard":
    col1, col2 = st.columns([4, 1])
    with col1:
        st.title("🏠 Security Operations Dashboard")
        st.caption("Real-Time Threat Intelligence & Alert Management")
    with col2:
        if not filtered_df.empty:
            stats_geo = st.session_state.geo.get_attack_statistics(filtered_df)
            report_buffer = generate_soc_report(filtered_df, stats_geo)
            st.download_button(label="📑 Generate Report", data=report_buffer, file_name=f"SOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", mime="application/pdf", use_container_width=True)
    
    st.markdown("---")
    
    if not filtered_df.empty:
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🔴 Critical", len(filtered_df[filtered_df['priority'] == 'CRITICAL']))
        col2.metric("🟠 High", len(filtered_df[filtered_df['priority'] == 'HIGH']))
        col3.metric("🟡 Medium", len(filtered_df[filtered_df['priority'] == 'MEDIUM']))
        col4.metric("🟢 Low", len(filtered_df[filtered_df['priority'] == 'LOW']))
        col5.metric("📊 Total", len(filtered_df))
        
        st.markdown("---")
        
        left_col, right_col = st.columns([2, 1])
        
        with left_col:
            st.subheader("🗺️ Global Threat Map")
            
            map_data = []
            for _, alert in filtered_df.iterrows():
                location = st.session_state.geo.get_location(alert['source_ip'])
                map_data.append({'lat': location['lat'], 'lon': location['lon'], 'country': location['country'], 'ip': alert['source_ip'], 'priority': alert['priority']})
            
            map_df = pd.DataFrame(map_data)
            stats_geo = st.session_state.geo.get_attack_statistics(filtered_df)
            
            fig = go.Figure()
            target_lat, target_lon = 33.6844, 73.0479
            
            for country, data in stats_geo.items():
                if country != 'Pakistan':
                    line_color = 'rgba(239,68,68,0.7)' if data['critical'] > 0 else 'rgba(251,146,60,0.6)' if data['high'] > 0 else 'rgba(250,204,21,0.5)'
                    line_width = 2.5 if data['critical'] > 0 else 2 if data['high'] > 0 else 1.5
                    fig.add_trace(go.Scattergeo(lon=[data['lon'], target_lon], lat=[data['lat'], target_lat], mode='lines', line=dict(width=line_width, color=line_color), showlegend=False, hoverinfo='skip'))
            
            for country, data in stats_geo.items():
                if country != 'Pakistan':
                    fig.add_trace(go.Scattergeo(lon=[data['lon']], lat=[data['lat']], mode='text', text=[country], textfont=dict(size=9, color='#94a3b8'), showlegend=False, hoverinfo='skip'))
            
            for _, alert_point in map_df.iterrows():
                color = {'CRITICAL': '#ef4444', 'HIGH': '#fb923c', 'MEDIUM': '#facc15', 'LOW': '#4ade80'}.get(alert_point['priority'], '#94a3b8')
                size = {'CRITICAL': 12, 'HIGH': 10, 'MEDIUM': 8, 'LOW': 6}.get(alert_point['priority'], 6)
                fig.add_trace(go.Scattergeo(lon=[alert_point['lon']], lat=[alert_point['lat']], mode='markers', marker=dict(size=size, color=color, line=dict(width=1.5, color='white'), opacity=0.9), showlegend=False, hovertemplate=f"<b>{alert_point['country']}</b><br>IP: {alert_point['ip']}<extra></extra>"))
            
            fig.add_trace(go.Scattergeo(lon=[target_lon], lat=[target_lat], mode='markers+text', marker=dict(size=20, color='#06b6d4', symbol='star', line=dict(width=3, color='white')), text=['TARGET'], textposition='top center', textfont=dict(size=11, color='#06b6d4', family='Arial Black'), showlegend=False))
            
            fig.update_geos(resolution=50, showcountries=True, countrycolor="#334155", countrywidth=1, showcoastlines=True, coastlinecolor="#475569", showland=True, landcolor="#1e293b", showocean=True, oceancolor="#0f172a", projection_type="natural earth")
            fig.update_layout(height=420, margin=dict(l=0, r=0, t=0, b=0), geo=dict(center=dict(lat=25, lon=40), projection_scale=1.2, bgcolor="#0f172a"), paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", showlegend=False)
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            
            st.markdown("")
            st.subheader("📈 Alert Timeline (24h)")
            
            filtered_df['timestamp_dt'] = pd.to_datetime(filtered_df['timestamp'])
            filtered_df['hour'] = filtered_df['timestamp_dt'].dt.hour
            hourly_counts = filtered_df.groupby('hour').size().reindex(range(24), fill_value=0).reset_index()
            hourly_counts.columns = ['hour', 'count']
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=hourly_counts['hour'], y=hourly_counts['count'], mode='lines+markers', fill='tozeroy', line=dict(color='#3b82f6', width=2), marker=dict(size=6, color='#60a5fa'), fillcolor='rgba(59,130,246,0.2)'))
            fig.update_layout(height=280, margin=dict(l=20, r=20, t=10, b=20), paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", xaxis=dict(title="Hour", showgrid=True, gridcolor='#334155', color='#94a3b8'), yaxis=dict(title="Alerts", showgrid=True, gridcolor='#334155', color='#94a3b8'), font=dict(color='#cbd5e1'))
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
        
        with right_col:
            st.subheader("📊 Priority")
            
            priority_counts = filtered_df['priority'].value_counts()
            fig = go.Figure(data=[go.Pie(labels=priority_counts.index, values=priority_counts.values, hole=0.65, marker=dict(colors=['#ef4444', '#fb923c', '#facc15', '#4ade80']), textfont=dict(color='white', size=12))])
            fig.update_layout(height=280, margin=dict(l=20, r=20, t=10, b=20), paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", font=dict(color='#cbd5e1'), showlegend=True, legend=dict(font=dict(color='#cbd5e1')))
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            
            st.markdown("")
            st.subheader("🎯 Top Threats")
            
            threat_counts = filtered_df['threat_type'].value_counts().head(5)
            fig = go.Figure(data=[go.Bar(y=threat_counts.index, x=threat_counts.values, orientation='h', marker=dict(color='#3b82f6'), text=threat_counts.values, textposition='auto')])
            fig.update_layout(height=280, margin=dict(l=20, r=20, t=10, b=20), paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", xaxis=dict(showgrid=False, color='#64748b'), yaxis=dict(showgrid=False, color='#cbd5e1'), font=dict(color='#cbd5e1'))
            st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
            
            st.markdown("")
            st.subheader("🌍 Origins")
            
            stats_list = []
            for country, data in stats_geo.items():
                if country != 'Pakistan':
                    stats_list.append({'Country': country, 'Count': data['count'], '🔴': data['critical'], '🟠': data['high']})
            
            if stats_list:
                stats_df = pd.DataFrame(stats_list).sort_values('Count', ascending=False).head(8)
                st.dataframe(stats_df.style.set_properties(**{'text-align': 'left', 'font-size': '0.85rem', 'color': '#cbd5e1', 'background-color': '#1e293b'}), use_container_width=True, height=260)
            else:
                st.info("No attack data")
    else:
        st.info("📭 No alerts found. Click 'Fetch Alerts'!")

# ALERTS PAGE - FIXED WITH PROPER COLORS
elif st.session_state.current_page == "Alerts":
    st.title("🚨 Security Alerts")
    st.caption("Real-Time Alert Feed with SOAR Status")
    st.markdown("---")
    
    if not filtered_df.empty:
        filtered_df_display = filtered_df.sort_values('priority_score', ascending=False).reset_index(drop=True)
        # Add SOAR status column
        soar_status_list = []
        for _, alert in filtered_df_display.iterrows():
            soar_exec = st.session_state.soar.get_execution_by_alert(alert['id'])
            if soar_exec:
                 soar_status_list.append(f"✅ Automated ({len(soar_exec[0]['actions'])} actions)")
            else:
                soar_status_list.append("⏺️ No Response")

        display_df = pd.DataFrame({
            'ID': range(1, len(filtered_df_display) + 1),
            'Time': pd.to_datetime(filtered_df_display['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S'),
            'Priority': filtered_df_display['priority'],
            'Score': filtered_df_display['priority_score'],
            'Severity': filtered_df_display['severity'].str.upper(),
            'Threat': filtered_df_display['threat_type'].str.replace('_', ' ').str.title(),
            'SOAR': soar_status_list,
            'Source IP': filtered_df_display['source_ip'],
            'Target': filtered_df_display['destination'],
            'Description': filtered_df_display['description'].str[:80] + '...'
        })
        
        # Color functions
        def color_priority(val):
            colors_map = {'CRITICAL': 'color: #ef4444; font-weight: bold; font-size: 0.95rem;', 'HIGH': 'color: #fb923c; font-weight: bold; font-size: 0.95rem;', 'MEDIUM': 'color: #facc15; font-weight: bold; font-size: 0.95rem;', 'LOW': 'color: #4ade80; font-weight: bold; font-size: 0.95rem;'}
            return colors_map.get(val, '')
        
        def color_severity(val):
            colors_map = {'CRITICAL': 'background-color: #7f1d1d; color: #fecaca; font-weight: bold; padding: 8px; border-radius: 4px;', 'HIGH': 'background-color: #7c2d12; color: #fed7aa; font-weight: bold; padding: 8px; border-radius: 4px;', 'MEDIUM': 'background-color: #713f12; color: #fef3c7; font-weight: bold; padding: 8px; border-radius: 4px;', 'LOW': 'background-color: #14532d; color: #bbf7d0; font-weight: bold; padding: 8px; border-radius: 4px;'}
            return colors_map.get(val, '')

        def color_soar(val):
            if '✅' in val:
                return 'background-color: #14532d; color: #bbf7d0; font-weight: bold; padding: 8px; border-radius: 4px;'
            else:
                return 'background-color: #1e293b; color: #94a3b8; padding: 8px;'

        # Apply styling using map (instead of deprecated applymap)
        styled_df = display_df.style\
            .map(color_priority, subset=['Priority'])\
            .map(color_severity, subset=['Severity'])\
            .map(color_soar, subset=['SOAR'])\
            .set_properties(**{'text-align': 'left', 'font-size': '0.9rem', 'background-color': '#1e293b', 'color': '#cbd5e1', 'border': '1px solid #334155', 'padding': '10px'})\
            .set_table_styles([
                {'selector': 'thead th', 'props': [('background-color', '#1e3a8a'), ('color', 'white'), ('font-weight', 'bold'), ('text-align', 'center'), ('padding', '12px'), ('border', '1px solid #334155'), ('font-size', '1rem')]},
                {'selector': 'tbody tr:hover', 'props': [('background-color', '#334155'), ('cursor', 'pointer')]},
                {'selector': 'tbody td', 'props': [('border', '1px solid #334155'), ('padding', '10px')]},
                {'selector': 'table', 'props': [('border-collapse', 'collapse'), ('width', '100%'), ('border', '2px solid #334155'), ('border-radius', '8px')]}
            ])
        
        st.dataframe(styled_df, use_container_width=True, height=600)

        # Alert details with SOAR actions
        st.markdown("---")
        st.subheader("📋 Alert Details & SOAR Actions")
        selected_alert_id = st.selectbox(
            "Select Alert to View Details",
            options=range(len(filtered_df_display)),
            format_func=lambda x: f"Alert #{x+1}: {filtered_df_display.iloc[x]['threat_type'].replace('_', ' ').title()} - {filtered_df_display.iloc[x]['priority']}"
            )

        if selected_alert_id is not None:
            alert_detail = filtered_df_display.iloc[selected_alert_id]

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Priority", alert_detail['priority'])
                st.metric("Score", alert_detail['priority_score'])
            with col2:
                st.metric("Threat Type", alert_detail['threat_type'].replace('_', ' ').title())
                st.metric("Source IP", alert_detail['source_ip'])
            with col3:
                st.metric("Target", alert_detail['destination'])
                st.metric("Severity", alert_detail['severity'].upper())
            
            st.markdown("**Description:**")
            st.info(alert_detail['description'])

            # Show SOAR actions
            soar_exec = st.session_state.soar.get_execution_by_alert(alert_detail['id'])
            if soar_exec:
                st.markdown("---")
                st.subheader("🤖 SOAR Automated Response")
                
                exec_data = soar_exec[0]
                
                st.success(f"**Playbook:** {exec_data['playbook_name']} ({exec_data['playbook_id']})")
                st.info(f"**Execution ID:** {exec_data['execution_id']}")
                st.write(f"**Status:** {exec_data['status'].upper()}")
                st.write(f"**Executed:** {exec_data['start_time'][:19]}")
                st.write(f"**Total Actions:** {exec_data['total_actions']}")
                st.write(f"**Success:** {exec_data['success_count']} | **Failed:** {exec_data['failed_count']}")
                
                st.markdown("**Actions Executed:**")
                
                for action in exec_data['actions']:
                    with st.expander(f"Step {action['step']}: {action['action'].replace('_', ' ').title()} - {action['status'].upper()}"):
                        if action['status'] == 'success':
                            st.success(f"✅ **Status:** Success")
                            st.write(f"**Message:** {action.get('message', 'Action completed successfully')}")
                            
                            # Show action-specific details
                            for key, value in action.items():
                                if key not in ['action', 'status', 'message', 'timestamp', 'step', 'critical']:
                                    st.write(f"**{key.replace('_', ' ').title()}:** {value}")
                        else:
                            st.error(f"❌ **Status:** Failed")
                            st.write(f"**Error:** {action.get('error', 'Unknown error')}")
                        
                        st.caption(f"Executed at: {action['timestamp'][:19]}")
            else:
                st.warning("⏺️ No automated response was triggered for this alert")
        
        st.markdown("---")

        col1, col2, col3 = st.columns(3)
        
        with col1:
            csv = filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button("📄 Export CSV", csv, f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv", use_container_width=True)
        
        with col2:
            json_data = filtered_df.to_json(orient='records', indent=2)
            st.download_button("📋 Export JSON", json_data, f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "application/json", use_container_width=True)
        
        with col3:
            try:
                excel_buffer = BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    filtered_df.to_excel(writer, index=False, sheet_name='Alerts')
                excel_buffer.seek(0)
                st.download_button("📊 Export Excel", excel_buffer, f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", use_container_width=True)
            except:
                pass
    else:
        st.info("📭 No alerts found. Click 'Fetch Alerts'!")

elif st.session_state.current_page == "Investigations":
    st.title("🔍 Active Investigations")
    st.caption("SOC Investigation Management")
    st.markdown("---")
    
    if not filtered_df.empty:
        critical_high = filtered_df[filtered_df['priority'].isin(['CRITICAL', 'HIGH'])]
        
        for alert_id in critical_high['id'].values:
            if alert_id not in st.session_state.investigations:
                st.session_state.investigations[alert_id] = {'status': 'New', 'assigned_to': 'Unassigned', 'soc_level': 'L1', 'notes': ''}
        
        status_counts = {'New': 0, 'In Progress': 0, 'Escalated': 0, 'Resolved': 0, 'Closed': 0}
        for alert_id in st.session_state.investigations:
            status = st.session_state.investigations[alert_id]['status']
            if status in status_counts:
                status_counts[status] += 1
        
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🆕 New", status_counts['New'])
        col2.metric("⏳ Active", status_counts['In Progress'])
        col3.metric("⬆️ Escalated", status_counts['Escalated'])
        col4.metric("✅ Resolved", status_counts['Resolved'])
        col5.metric("🔒 Closed", status_counts['Closed'])
        
        st.markdown("---")
        
        for idx, alert in critical_high.iterrows():
            alert_id = alert['id']
            inv_data = st.session_state.investigations.get(alert_id, {})
            status_emoji = {'New': '🆕', 'In Progress': '⏳', 'Escalated': '⬆️', 'Resolved': '✅', 'Closed': '🔒'}.get(inv_data.get('status', 'New'), '⚪')
            
            with st.expander(f"{status_emoji} {alert['threat_type'].replace('_', ' ').title()} - {alert['source_ip']} [{inv_data.get('status', 'New')}]"):
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    st.markdown(f"**ID:** {alert_id[:40]}...")
                    st.markdown(f"**Desc:** {alert['description']}")
                    st.markdown(f"**Priority:** {alert['priority']} ({alert['priority_score']})")
                
                with col2:
                    new_status = st.selectbox("Status", ['New', 'In Progress', 'Escalated', 'Resolved', 'Closed'], index=['New', 'In Progress', 'Escalated', 'Resolved', 'Closed'].index(inv_data.get('status', 'New')), key=f"status_{alert_id}")
                    new_level = st.selectbox("Level", ['L1', 'L2', 'L3'], index=['L1', 'L2', 'L3'].index(inv_data.get('soc_level', 'L1')), key=f"level_{alert_id}")
                
                with col3:
                    new_assigned = st.selectbox("Assigned", ['Unassigned', 'Analyst-1', 'Analyst-2', 'Analyst-3'], index=['Unassigned', 'Analyst-1', 'Analyst-2', 'Analyst-3'].index(inv_data.get('assigned_to', 'Unassigned')), key=f"assigned_{alert_id}")
                
                notes = st.text_area("Notes", value=inv_data.get('notes', ''), key=f"notes_{alert_id}", height=80)
                
                if st.button("💾 Update", key=f"update_{alert_id}"):
                    st.session_state.investigations[alert_id] = {'status': new_status, 'assigned_to': new_assigned, 'soc_level': new_level, 'notes': notes}
                    st.success("✅ Updated!")
                    st.rerun()
    else:
        st.info("No investigations")

elif st.session_state.current_page == "Analytics":
    st.title("📊 Threat Analytics")
    st.caption("Security Metrics")
    st.markdown("---")
    
    if not filtered_df.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Priority")
            priority_counts = filtered_df['priority'].value_counts()
            fig = px.pie(values=priority_counts.values, names=priority_counts.index, color=priority_counts.index, color_discrete_map={'CRITICAL': '#ef4444', 'HIGH': '#fb923c', 'MEDIUM': '#facc15', 'LOW': '#4ade80'}, hole=0.4)
            fig.update_layout(height=350, paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", font=dict(color='#cbd5e1'))
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Threats")
            threat_counts = filtered_df['threat_type'].value_counts()
            fig = px.bar(x=threat_counts.values, y=threat_counts.index, orientation='h', color=threat_counts.values, color_continuous_scale='Blues')
            fig.update_layout(height=350, paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", xaxis=dict(showgrid=False, color='#94a3b8'), yaxis=dict(showgrid=False, color='#cbd5e1'), font=dict(color='#cbd5e1'))
            st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        st.subheader("📈 Trend")
        
        filtered_df['timestamp_dt'] = pd.to_datetime(filtered_df['timestamp'])
        filtered_df['date'] = filtered_df['timestamp_dt'].dt.date
        daily_counts = filtered_df.groupby('date').size().reset_index(name='count')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=daily_counts['date'], y=daily_counts['count'], mode='lines+markers', fill='tozeroy', line=dict(color='#3b82f6', width=2), marker=dict(size=8, color='#60a5fa'), fillcolor='rgba(59,130,246,0.2)'))
        fig.update_layout(height=350, paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", xaxis=dict(title="Date", showgrid=True, gridcolor='#334155', color='#94a3b8'), yaxis=dict(title="Alerts", showgrid=True, gridcolor='#334155', color='#94a3b8'), font=dict(color='#cbd5e1'))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data")

elif st.session_state.current_page == "Threat Map":
    st.title("🗺️ Global Threat Map")
    st.caption("Real-Time Attack Origins")
    st.markdown("---")
    
    if not filtered_df.empty:
        map_data = []
        for _, alert in filtered_df.iterrows():
            location = st.session_state.geo.get_location(alert['source_ip'])
            map_data.append({'lat': location['lat'], 'lon': location['lon'], 'country': location['country'], 'ip': alert['source_ip'], 'threat': alert['threat_type'], 'priority': alert['priority'], 'description': alert['description'][:60]})
        
        map_df = pd.DataFrame(map_data)
        stats_geo = st.session_state.geo.get_attack_statistics(filtered_df)
        
        fig = go.Figure()
        target_lat, target_lon = 33.6844, 73.0479
        
        for country, data in stats_geo.items():
            if country != 'Pakistan':
                line_color = 'rgba(239,68,68,0.8)' if data['critical'] > 0 else 'rgba(251,146,60,0.7)' if data['high'] > 0 else 'rgba(250,204,21,0.6)'
                line_width = 3 if data['critical'] > 0 else 2.5 if data['high'] > 0 else 2
                fig.add_trace(go.Scattergeo(lon=[data['lon'], target_lon], lat=[data['lat'], target_lat], mode='lines', line=dict(width=line_width, color=line_color), showlegend=False, hoverinfo='skip'))
        
        for country, data in stats_geo.items():
            if country != 'Pakistan':
                fig.add_trace(go.Scattergeo(lon=[data['lon']], lat=[data['lat']], mode='text', text=[country], textfont=dict(size=11, color='#e2e8f0', family='Arial'), showlegend=False, hoverinfo='skip'))
        
        for _, alert_point in map_df.iterrows():
            color = {'CRITICAL': '#ef4444', 'HIGH': '#fb923c', 'MEDIUM': '#facc15', 'LOW': '#4ade80'}.get(alert_point['priority'], '#94a3b8')
            size = {'CRITICAL': 14, 'HIGH': 11, 'MEDIUM': 9, 'LOW': 7}.get(alert_point['priority'], 7)
            hover_text = f"<b>{alert_point['country']}</b><br>IP: {alert_point['ip']}<br>Priority: {alert_point['priority']}<br>Threat: {alert_point['threat'].replace('_', ' ').title()}<br>{alert_point['description']}"
            fig.add_trace(go.Scattergeo(lon=[alert_point['lon']], lat=[alert_point['lat']], text=hover_text, mode='markers', marker=dict(size=size, color=color, line=dict(width=2, color='white'), opacity=0.9), hovertemplate='%{text}<extra></extra>', showlegend=False))
        
        fig.add_trace(go.Scattergeo(lon=[target_lon], lat=[target_lat], mode='markers+text', marker=dict(size=24, color='#06b6d4', symbol='star', line=dict(width=4, color='white')), text=['TARGET'], textposition='top center', textfont=dict(size=13, color='#06b6d4', family='Arial Black'), hovertemplate='<b>Pakistan</b><extra></extra>', showlegend=False))
        
        fig.update_geos(resolution=50, showcountries=True, countrycolor="#334155", countrywidth=1.5, showcoastlines=True, coastlinecolor="#475569", showland=True, landcolor="#1e293b", showocean=True, oceancolor="#0f172a", projection_type="natural earth")
        fig.update_layout(height=700, margin=dict(l=0, r=0, t=0, b=0), geo=dict(center=dict(lat=25, lon=40), projection_scale=1.3, bgcolor="#0f172a"), paper_bgcolor="#0f172a", plot_bgcolor="#0f172a", showlegend=False)
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
        
        st.markdown("---")
        st.subheader("🌍 Statistics")
        
        stats_list = []
        for country, data in stats_geo.items():
            stats_list.append({'Country': country, 'Total': data['count'], '🔴': data['critical'], '🟠': data['high'], '🟡': data['medium'], '🟢': data['low']})
        
        if stats_list:
            stats_df = pd.DataFrame(stats_list).sort_values('Total', ascending=False)
            st.dataframe(stats_df, use_container_width=True, height=400)
    else:
        st.info("No data")

elif st.session_state.current_page == "SOAR":
    st.title("🤖 Security Orchestration & Automated Response")
    st.caption("Enterprise-Grade Automated Threat Response Platform")
    st.markdown("---")
    
    # SOAR Statistics
    soar_stats = st.session_state.soar.get_statistics()
    
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("🎯 Playbooks Executed", soar_stats['total_executions'])
    col2.metric("⚡ Total Actions", soar_stats['total_actions'])
    col3.metric("✅ Success Rate", f"{soar_stats['success_rate']}%")
    col4.metric("📊 Last 24h", soar_stats['last_24h_executions'])
    col5.metric("🚫 IPs Blocked", soar_stats['actions_by_type'].get('block_ip', 0))
    
    st.markdown("---")
    
    # Tabs for organization
    tab1, tab2, tab3, tab4 = st.tabs(["⚙️ Configuration", "📚 Playbooks", "📜 Execution History", "📊 Analytics"])
    
    # TAB 1: Configuration
    with tab1:
        st.subheader("⚙️ SOAR Configuration")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.session_state.soar.enabled = st.checkbox(
                "🔴 Enable Automated Response (Master Switch)",
                value=st.session_state.soar.enabled,
                help="When enabled, SOAR will automatically respond to threats in real-time"
            )
            
            st.session_state.soar.auto_block_threshold = st.slider(
                "Auto-block threshold (failed login attempts)",
                min_value=3,
                max_value=20,
                value=st.session_state.soar.auto_block_threshold,
                help="Block IP after this many failed attempts"
            )
            
            st.markdown("**Automation Toggles:**")
            col_a, col_b = st.columns(2)
            with col_a:
                st.session_state.soar.auto_isolate = st.checkbox("Auto-isolate compromised hosts", value=st.session_state.soar.auto_isolate)
                st.session_state.soar.auto_ticket = st.checkbox("Auto-create tickets", value=st.session_state.soar.auto_ticket)
            with col_b:
                st.session_state.soar.auto_notify = st.checkbox("Auto-send notifications", value=st.session_state.soar.auto_notify)
                st.session_state.soar.email_notifications = st.checkbox("Enable email alerts", value=st.session_state.soar.email_notifications)
            
            st.markdown("**Notification Configuration:**")
            webhook_url = st.text_input(
                "Slack Webhook URL",
                value=st.session_state.soar.notification_webhook or "",
                placeholder="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
                help="Receive real-time SOAR notifications in Slack"
            )
            
            if webhook_url:
                st.session_state.soar.notification_webhook = webhook_url
            
            if st.session_state.soar.email_notifications:
                email_list = st.text_area(
                    "Email Recipients (one per line)",
                    value='\n'.join(st.session_state.soar.email_recipients),
                    placeholder="security@company.com\nsoc@company.com\nciso@company.com"
                )
                st.session_state.soar.email_recipients = [e.strip() for e in email_list.split('\n') if e.strip()]
            
            if st.button("💾 Save Configuration", use_container_width=True):
                st.session_state.soar.save_configuration()
                st.success("✅ SOAR configuration saved successfully!")
                st.rerun()
        
        with col2:
            st.markdown("**Status Dashboard:**")
            
            if st.session_state.soar.enabled:
                st.success("🟢 SOAR ACTIVE")
            else:
                st.error("🔴 SOAR DISABLED")
            
            st.info(f"**Playbooks:** 6 Active")
            st.info(f"**Actions:** {len(st.session_state.soar.get_executions())} Executed")
            
            if soar_stats['last_execution']:
                st.info(f"**Last Run:** {soar_stats['last_execution'][:19]}")
    
    # TAB 2: Playbooks
    with tab2:
        st.subheader("📚 Enterprise Playbooks")
        
        all_playbooks = st.session_state.soar.get_all_playbooks()
        
        for playbook in all_playbooks:
            status_icon = "✅" if playbook['enabled'] else "⏸️"
            auto_icon = "🤖" if playbook['auto_execute'] else "👤"
            
            with st.expander(f"{status_icon} {auto_icon} {playbook['name']} ({playbook['id']})"):
                st.write(f"**Description:** {playbook['description']}")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write(f"**Trigger Type:** {playbook['trigger'].get('threat_type', 'N/A')}")
                with col2:
                    st.write(f"**Priority:** {', '.join(playbook['trigger'].get('priority', []))}")
                with col3:
                    st.write(f"**Total Actions:** {len(playbook['actions'])}")
                
                st.markdown("**Automated Actions:**")
                for action in playbook['actions']:
                    critical_badge = "🔴" if action['critical'] else "🔵"
                    st.write(f"{critical_badge} **Step {action['step']}:** {action['action'].replace('_', ' ').title()}")
                
                # Playbook controls
                col_a, col_b = st.columns(2)
                with col_a:
                    new_enabled = st.checkbox(
                        "Enabled",
                        value=playbook['enabled'],
                        key=f"enabled_{playbook['id']}"
                    )
                with col_b:
                    new_auto = st.checkbox(
                        "Auto-Execute",
                        value=playbook['auto_execute'],
                        key=f"auto_{playbook['id']}"
                    )
                
                if st.button(f"Update {playbook['id']}", key=f"update_{playbook['id']}"):
                    st.session_state.soar.update_playbook(
                        playbook['id'],
                        {'enabled': new_enabled, 'auto_execute': new_auto}
                    )
                    st.success(f"✅ Playbook {playbook['id']} updated!")
                    st.rerun()
    
    # TAB 3: Execution History
    with tab3:
        st.subheader("📜 SOAR Execution History")
        
        executions = st.session_state.soar.get_executions(limit=50)
        
        if executions:
            for exec_data in executions:
                status_color = "🟢" if exec_data['status'] == 'completed' else "🔴"
                
                # FIXED: Use .get() with default values to prevent KeyError
                alert_type = exec_data.get('alert_type', 'Unknown')
                playbook_name = exec_data.get('playbook_name', 'Unknown Playbook')
                start_time = exec_data.get('start_time', datetime.now().isoformat())
                total_actions = exec_data.get('total_actions', 0)

                with st.expander(
                    f"{status_color} {exec_data['playbook_name']} | "
                    f"{exec_data['alert_type'].replace('_', ' ').title()} | "
                    f"{exec_data['start_time'][:19]} | "
                    f"{exec_data['total_actions']} actions"
                ):
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                       st.metric("Execution ID", exec_data.get('execution_id', 'N/A')[:8])
                       st.write(f"**Playbook:** {exec_data.get('playbook_id', 'N/A')}")
                
                    with col2:
                       st.metric("Alert Priority", exec_data.get('alert_priority', 'N/A'))
                       st.write(f"**Threat:** {alert_type.replace('_', ' ').title()}")
                
                    with col3:
                       st.metric("Total Actions", total_actions)
                       st.write(f"**Success:** {exec_data.get('success_count', 0)}")
                
                    with col4:
                       st.metric("Status", exec_data.get('status', 'Unknown').upper())
                       st.write(f"**Failed:** {exec_data.get('failed_count', 0)}")
                    
                    st.markdown("**Alert Details:**")
                    st.write(f"• **Source IP:** {exec_data.get('source_ip', 'N/A')}")
                    st.write(f"• **Target:** {exec_data.get('destination', 'N/A')}")
                    st.write(f"• **Started:** {start_time[:19]}")
                    end_time = exec_data.get('end_time', 'In Progress')
                    st.write(f"• **Completed:** {end_time[:19] if end_time != 'In Progress' else end_time}")
                    
                    st.markdown("**Actions Executed:**")
                    for action in exec_data.get('actions', []):
                        if action.get('status') == 'success':
                            st.success(
                                f"✅ Step {action.get('step', '?')}: "
                                f"{action.get('action', 'Unknown').replace('_', ' ').title()} - "
                                f"{action.get('message', 'Success')}"
                            )
                        else:
                            st.error(
                                f"❌ Step {action.get('step', '?')}: "
                                f"{action.get('action', 'Unknown').replace('_', ' ').title()} - "
                                f"{action.get('error', 'Failed')}"
                            )
        else:
            st.info("📭 No SOAR executions yet. SOAR will automatically respond when critical alerts are detected.")
    
    # TAB 4: Analytics
    with tab4:
        st.subheader("📊 SOAR Analytics")
        
        if soar_stats['total_executions'] > 0:
            # Actions by type
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Actions by Type:**")
                actions_data = soar_stats.get('actions_by_type', {})

                if actions_data:
                    import plotly.express as px

                    fig = px.bar(
                        x=list(actions_data.values()),
                        y=[k.replace('_', ' ').title() for k in actions_data.keys()],
                        orientation='h',
                        title="Action Execution Count",
                        labels={'x': 'Count', 'y': 'Action Type'}
                    )
                    fig.update_layout(
                        height=400,
                        paper_bgcolor="#0f172a",
                        plot_bgcolor="#0f172a",
                        font=dict(color='#cbd5e1'),
                        xaxis=dict(showgrid=True, gridcolor='#334155'),
                        yaxis=dict(showgrid=False)
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No action data yet")
            
            with col2:
                st.markdown("**Playbook Executions:**")
                playbook_data = soar_stats.get('executions_by_playbook', {})

                if playbook_data:
                    fig = px.pie(
                        values=list(playbook_data.values()),
                        names=list(playbook_data.keys()),
                        title="Executions by Playbook"
                    )
                    fig.update_layout(
                        height=400,
                        paper_bgcolor="#0f172a",
                        plot_bgcolor="#0f172a",
                        font=dict(color='#cbd5e1')
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No playbook data yet")
            
            # Summary stats
            st.markdown("**Summary Statistics:**")
            col_a, col_b, col_c, col_d = st.columns(4)
            actions_by_type = soar_stats.get('actions_by_type', {})
            with col_a:
                st.metric("IPs Blocked", actions_by_type.get('block_ip', 0))
            with col_b:
                st.metric("Hosts Isolated", actions_by_type.get('isolate_host', 0))
            with col_c:
                st.metric("Tickets Created", actions_by_type.get('create_ticket', 0))
            with col_d:
                st.metric("Notifications Sent", actions_by_type.get('send_notification', 0))
        
        else:
            st.info("📊 No analytics data available yet. Execute some playbooks to see analytics.")
            
elif st.session_state.current_page == "Settings":
    st.title("⚙️ Settings")
    st.caption("System Configuration")
    st.markdown("---")
    
    st.subheader("🔧 Configuration")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Severity Weights**")
        st.slider("Critical", 0, 100, 50)
        st.slider("High", 0, 100, 30)
        st.slider("Medium", 0, 100, 20)
        st.slider("Low", 0, 100, 10)
    
    with col2:
        st.markdown("**Asset Weights**")
        st.slider("Production", 0, 100, 40)
        st.slider("Staging", 0, 100, 20)
        st.slider("Development", 0, 100, 10)
    
    st.markdown("---")
    st.subheader("📊 System Info")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("DB Size", f"{stats['total']}")
    col2.metric("Investigations", len(st.session_state.investigations))
    col3.metric("Status", "🟢 Online")

st.markdown("---")
st.caption("🛡️ SOC Alert Triage System v2.0 | Powered by Wazuh & AI Rule Engine")