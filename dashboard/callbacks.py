"""
Dashboard Callbacks - Pure Dash callbacks only
"""

import logging
import json
from datetime import datetime, timezone
from dash import Input, Output, State, html, dcc, dash_table, ctx
import dash_bootstrap_components as dbc
import sqlite3
import plotly.graph_objs as go
import plotly.express as px

from .layout import load_i18n
from . import data as dbdata
from incidents.workflow import assign_owner, set_status, add_note

logger = logging.getLogger(__name__)

def register_callbacks(app, db):
    """Register all Dash callbacks"""
    
    @app.callback(
        Output("tick", "interval"),
        Input("refresh_seconds", "value"),
    )
    def set_interval(seconds):
        """Update refresh interval"""
        return int(seconds) * 1000

    @app.callback(
        Output("page", "children"),
        Input("tabs", "value"),
        Input("tick", "n_intervals"),
        Input("lang", "value"),
    )
    def render_page(tab, n_intervals, lang):
        """Render page content based on selected tab"""
        t = load_i18n(lang)
        
        try:
            if tab == "overview":
                return render_overview(t, lang, db)
            elif tab == "alerts":
                return render_alerts(t, lang, db)
            elif tab == "incidents":
                return render_incidents(t, lang, db)
            elif tab == "features":
                return render_features(t, lang, db)
            elif tab == "charts":
                return render_charts(t, lang, db)
            elif tab == "events":
                return render_events(t, lang, db)
            elif tab == "reports":
                return render_reports(t, lang, db)
            elif tab == "audit":
                return render_audit(t, lang, db)
            elif tab == "ai":
                return render_ai_page(t, lang, db)
            elif tab == "incident_details":
                return render_incident_details(t, lang, db)
            elif tab == "kpis":
                return render_kpis(t, lang, db)
            else:
                return html.Div("Page not found")
        except Exception as e:
            logger.error(f"Error rendering page: {e}")
            return html.Div(
                f"Error loading page: {str(e)[:100]}", 
                style={
                    "color": "#e74c3c", 
                    "padding": "40px", 
                    "textAlign": "center",
                    "fontSize": "18px"
                }
            )

    # ========== PAGE RENDERERS ==========

    def render_overview(t, lang, db):
        """Render overview page"""
        try:
            conn = sqlite3.connect(db.db_path)
            conn.row_factory = sqlite3.Row
            
            now = datetime.now()
            last_5m = (now - timedelta(minutes=5)).isoformat()
            last_24h = (now - timedelta(hours=24)).isoformat()
            
            cur = conn.execute("SELECT COUNT(*) as count FROM events WHERE timestamp >= ? OR ts_utc >= ?", 
                            (last_5m, last_5m))
            row = cur.fetchone()
            events_count = row['count'] if row else 0
            
            cur = conn.execute("SELECT COUNT(*) as count FROM alerts WHERE timestamp >= ? OR ts_utc >= ?", 
                            (last_24h, last_24h))
            row = cur.fetchone()
            alerts_count = row['count'] if row else 0
            
            cur = conn.execute("SELECT COUNT(*) as count FROM incidents WHERE status IN ('OPEN', 'open', 'investigating', 'INVESTIGATING')")
            row = cur.fetchone()
            incidents_count = row['count'] if row else 0
            
            cur = conn.execute("SELECT COUNT(*) as count FROM reports")
            row = cur.fetchone()
            reports_count = row['count'] if row else 0
            
            conn.close()
            
            return html.Div([
                html.H3(t["overview"], style={"marginBottom": "20px", "color": "#2c3e50"}),
                html.P(
                    f"Real-time SOC Dashboard • Last updated: {datetime.now().strftime('%H:%M:%S')}",
                    style={"color": "#7f8c8d", "fontSize": "16px", "lineHeight": "1.6"}
                ),
                html.Div(
                    style={
                        "display": "grid",
                        "gridTemplateColumns": "repeat(4, 1fr)",
                        "gap": "20px",
                        "marginTop": "30px"
                    },
                    children=[
                        create_stat_card("📊", t.get("kpi_cards", {}).get("events_5m", "Events"), 
                                    str(events_count), "#3498db"),
                        create_stat_card("🚨", t.get("kpi_cards", {}).get("alerts_24h", "Alerts"), 
                                    str(alerts_count), "#e74c3c"),
                        create_stat_card("⚠️", t.get("kpi_cards", {}).get("open_incidents", "Incidents"), 
                                    str(incidents_count), "#f39c12"),
                        create_stat_card("🔒", "Reports", str(reports_count), "#2ecc71")
                    ]
                )
            ])
        except Exception as e:
            logger.error(f"Error rendering overview: {e}")
            return html.Div([
                html.H3(t["overview"], style={"marginBottom": "20px", "color": "#2c3e50"}),
                html.Div(f"Error loading data: {str(e)[:100]}", 
                        style={"color": "#e74c3c", "padding": "20px", "textAlign": "center"}),
            ])

    def render_alerts(t, lang, db):
        """Render alerts page"""
        return html.Div([
            html.H3(t.get("alerts", "Alerts"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Alert data will appear here...", style={"color": "#7f8c8d"})
        ])

    def render_incidents(t, lang, db):
        """Render incidents page"""
        return html.Div([
            html.H3(t.get("incidents", "Incidents"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Incident data will appear here...", style={"color": "#7f8c8d"})
        ])

    def render_features(t, lang, db):
        """Render features page"""
        return html.Div([
            html.H3(t.get("features", "Features"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Feature data will appear here...", style={"color": "#7f8c8d"})
        ])

    def render_charts(t, lang, db):
        """Render charts page"""
        return html.Div([
            html.H3(t.get("charts", "Charts"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Charts will appear here...", style={"color": "#7f8c8d"})
        ])

    def render_events(t, lang, db):
        """Render events page"""
        return html.Div([
            html.H3(t.get("events", "Events"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Event data will appear here...", style={"color": "#7f8c8d"})
        ])

    def render_reports(t, lang, db):
        """Render reports page"""
        return html.Div([
            html.H3(t.get("reports", "Reports"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Report data will appear here...", style={"color": "#7f8c8d"})
        ])

    def render_audit(t, lang, db):
        """Render audit page"""
        return html.Div([
            html.H3(t.get("audit", "Audit Log"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.Div([
                html.P("Full audit functionality is available at:", style={"marginBottom": "10px"}),
                html.A(
                    "/audit",
                    href="/audit",
                    style={
                        "display": "inline-block",
                        "padding": "10px 20px",
                        "backgroundColor": "#3498db",
                        "color": "white",
                        "textDecoration": "none",
                        "borderRadius": "5px",
                        "fontWeight": "bold"
                    }
                )
            ], style={
                "textAlign": "center",
                "padding": "40px",
                "backgroundColor": "#f8f9fa",
                "borderRadius": "10px",
                "marginTop": "20px"
            })
        ])

    def render_ai_page(t, lang, db):
        """Render AI Analytics page"""
        try:
            conn = sqlite3.connect(db.db_path)
            conn.row_factory = sqlite3.Row
            
            timeseries_data = dbdata.ai_timeseries(conn, minutes=15)
            latest_scores = dbdata.latest_ai_scores(conn, limit=100)
            model_status = dbdata.get_ai_model_status(conn)
            
            conn.close()
            
            # Create chart
            if timeseries_data:
                fig = go.Figure()
                
                fig.add_trace(go.Scatter(
                    x=[x["timestamp"] for x in timeseries_data],
                    y=[x["value"] for x in timeseries_data],
                    mode="lines+markers",
                    name="Anomaly Score",
                    line=dict(color="#e74c3c", width=2)
                ))
                
                fig.update_layout(
                    title=t.get("ai_page", {}).get("chart_title", "Anomaly Score Over Time"),
                    xaxis_title="Time",
                    yaxis_title="Anomaly Score",
                    yaxis=dict(range=[0, 1], tickformat=".2f"),
                    plot_bgcolor="white",
                    paper_bgcolor="white"
                )
                
                chart = dcc.Graph(figure=fig, style={"height": "400px"})
            else:
                chart = html.Div("No data available", style={"textAlign": "center", "padding": "50px"})
            
            return html.Div([
                html.H3(t.get("ai", "AI Analytics"), style={"color": "#2c3e50"}),
                chart
            ])
            
        except Exception as e:
            logger.error(f"Error rendering AI page: {e}")
            return html.Div(f"Error: {e}")

    def render_incident_details(t, lang, db):
        """Render incident details page"""
        return html.Div([
            html.H3(t.get("incident_details", "Incident Details"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("Incident details page - Under construction", style={"color": "#7f8c8d"})
        ])

    def render_kpis(t, lang, db):
        """Render KPIs page"""
        return html.Div([
            html.H3(t.get("kpis", "KPIs"), style={"marginBottom": "20px", "color": "#2c3e50"}),
            html.P("KPIs page - Under construction", style={"color": "#7f8c8d"})
        ])

    @app.callback(
        Output("wf_action_result", "children"),
        Input("btn_assign", "n_clicks"),
        Input("btn_status", "n_clicks"),
        Input("btn_note", "n_clicks"),
        Input("btn_close", "n_clicks"),
        State("incident_pick", "value"),
        State("wf_owner", "value"),
        State("wf_status", "value"),
        State("wf_note", "value"),
        State("wf_close_reason", "value"),
        prevent_initial_call=True
    )
    def handle_workflow_actions(n_assign, n_status, n_note, n_close, 
                               incident_id, owner, status, note, close_reason):
        """معالجة أزرار سير العمل"""
        if not incident_id:
            return "⚠️ No incident selected"
        
        trigger = ctx.triggered_id
        
        try:
            import sqlite3
            from incidents.workflow import assign_owner, set_status, add_note
            
            conn = sqlite3.connect(db.db_path)
            
            if trigger == "btn_assign":
                if not owner or not str(owner).strip():
                    return "❌ Owner name is required"
                assign_owner(conn, int(incident_id), str(owner).strip())
                add_note(conn, int(incident_id), f"Owner assigned to: {owner}", actor="dashboard")
                return f"✅ Owner assigned: {owner}"
            
            elif trigger == "btn_status":
                if not status:
                    return "❌ Status is required"
                set_status(conn, int(incident_id), str(status))
                add_note(conn, int(incident_id), f"Status changed to: {status}", actor="dashboard")
                return f"✅ Status updated: {status}"
            
            elif trigger == "btn_note":
                if not note or not str(note).strip():
                    return "❌ Note cannot be empty"
                add_note(conn, int(incident_id), str(note).strip(), actor="dashboard")
                return "✅ Note added"
            
            elif trigger == "btn_close":
                reason = (close_reason or "").strip()
                if not reason:
                    return "❌ Close reason is required"
                set_status(conn, int(incident_id), "CLOSED", reason=reason)
                add_note(conn, int(incident_id), f"Incident closed. Reason: {reason}", actor="dashboard")
                return f"✅ Incident closed. Reason: {reason}"
            
            conn.close()
            return "No action"
            
        except Exception as e:
            logger.error(f"Workflow action error: {e}")
            return f"❌ Error: {e}"
    # ========== UTILITY FUNCTIONS ==========

    def create_stat_card(icon, title, value, color):
        """Create a statistic card"""
        return html.Div(
            style={
                "backgroundColor": "#ffffff",
                "border": f"2px solid {color}",
                "borderRadius": "10px",
                "padding": "25px",
                "textAlign": "center",
                "boxShadow": "0 4px 6px rgba(0,0,0,0.1)"
            },
            children=[
                html.Div(icon, style={"fontSize": "40px", "marginBottom": "15px"}),
                html.Div(title, style={"fontSize": "16px", "color": "#7f8c8d", "marginBottom": "10px"}),
                html.Div(value, style={"fontSize": "32px", "fontWeight": "bold", "color": color})
            ]
        )
    