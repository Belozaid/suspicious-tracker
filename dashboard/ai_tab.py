"""
AI Dashboard Tab - تبويب الذكاء الاصطناعي في لوحة التحكم
واجهة متكاملة لعرض نتائج AI والتحكم بالنماذج
"""

from dash import dcc, html, dash_table
import plotly.graph_objs as go
from datetime import datetime, timedelta
import pandas as pd

def create_ai_tab_content(data_manager, translations):
    """إنشاء محتوى تبويب الذكاء الاصطناعي"""
    
    return html.Div([
        # ================= Header Section =================
        html.Div([
            html.H2("🤖 نظام الذكاء الاصطناعي - الكشف المتقدم", 
                   className="section-title"),
            html.P("نظام كشف الشذوذ باستخدام Isolation Forest والتحليل الهجين",
                  className="section-subtitle"),
        ], className="section-header"),
        
        # ================= Quick Stats =================
        html.Div([
            html.Div([
                html.Div([
                    html.H4("🎯 حالة النماذج", className="stats-title"),
                    html.Div(id="ai-model-status", className="stats-content")
                ], className="stats-card"),
                
                html.Div([
                    html.H4("📊 أداء الكشف", className="stats-title"),
                    html.Div(id="ai-performance", className="stats-content")
                ], className="stats-card"),
                
                html.Div([
                    html.H4("⚡ القرارات الهجينة", className="stats-title"),
                    html.Div(id="hybrid-decisions", className="stats-content")
                ], className="stats-card"),
            ], className="stats-grid"),
        ], className="mb-4"),
        
        # ================= Charts Section =================
        html.Div([
            html.Div([
                html.H4("📈 درجات الشذوذ عبر الزمن", className="chart-title"),
                dcc.Graph(id="anomaly-scores-chart", className="chart-container"),
                dcc.Interval(id='ai-chart-interval', interval=30000)
            ], className="chart-card"),
            
            html.Div([
                html.H4("🎭 توزيع الشدة", className="chart-title"),
                dcc.Graph(id="severity-distribution-chart", className="chart-container")
            ], className="chart-card"),
        ], className="charts-grid"),
        
        # ================= Model Control =================
        html.Div([
            html.H4("⚙️ التحكم بالنماذج", className="section-title"),
            html.Div([
                html.Button("🔄 تدريب نموذج جديد", 
                          id="train-model-btn", 
                          className="btn btn-primary mr-2"),
                html.Button("📊 تحديث البيانات", 
                          id="refresh-ai-btn", 
                          className="btn btn-secondary"),
                html.Button("📋 تقرير الأداء", 
                          id="ai-report-btn", 
                          className="btn btn-info ml-2"),
            ], className="control-buttons mb-3"),
            
            html.Div([
                html.Label("اختر النموذج النشط:", className="form-label"),
                dcc.Dropdown(
                    id="active-model-dropdown",
                    options=[],
                    placeholder="اختر نموذج...",
                    className="model-dropdown"
                ),
            ], className="model-control"),
        ], className="control-section"),
        
        # ================= AI Detections Table =================
        html.Div([
            html.H4("🔍 الكشوفات الأخيرة", className="section-title"),
            dash_table.DataTable(
                id='ai-detections-table',
                columns=[
                    {"name": "الوقت", "id": "timestamp", "type": "datetime"},
                    {"name": "درجة الشذوذ", "id": "anomaly_score"},
                    {"name": "الشدة", "id": "severity"},
                    {"name": "الثقة", "id": "confidence"},
                    {"name": "النموذج", "id": "model_id"},
                    {"name": "التفاصيل", "id": "details"}
                ],
                page_size=10,
                filter_action="native",
                sort_action="native",
                style_table={'overflowX': 'auto'},
                style_cell={'textAlign': 'center'},
                style_header={
                    'backgroundColor': 'rgb(30, 30, 30)',
                    'color': 'white',
                    'fontWeight': 'bold'
                },
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{severity} = "CRITICAL"'},
                        'backgroundColor': '#ffcccc',
                        'color': '#cc0000',
                        'fontWeight': 'bold'
                    },
                    {
                        'if': {'filter_query': '{severity} = "HIGH"'},
                        'backgroundColor': '#ffe6cc',
                        'color': '#e68a00'
                    },
                    {
                        'if': {'filter_query': '{severity} = "MEDIUM"'},
                        'backgroundColor': '#ffffcc',
                        'color': '#999900'
                    }
                ]
            )
        ], className="table-section"),
        
        # ================= Hybrid Decisions =================
        html.Div([
            html.H4("🤝 القرارات الهجينة", className="section-title"),
            html.Div(id="hybrid-decisions-details", className="hybrid-details")
        ], className="hybrid-section"),
        
        # ================= Feature Importance =================
        html.Div([
            html.H4("📊 أهمية الميزات", className="section-title"),
            dcc.Graph(id="feature-importance-chart", className="feature-chart")
        ], className="feature-section"),
        
        # ================= Hidden Components =================
        dcc.Store(id='ai-data-store'),
        dcc.Store(id='model-status-store'),
        dcc.Interval(id='ai-update-interval', interval=60000)
    ])