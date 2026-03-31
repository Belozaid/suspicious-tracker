"""
Dashboard Layout
"""

import json
from pathlib import Path
from dash import dcc, html
import dash_bootstrap_components as dbc
from datetime import datetime  # ← تأكد من وجود هذا السطر

I18N_DIR = Path(__file__).parent / "i18n"

def load_i18n(lang: str) -> dict:
    """Load translation file"""
    try:
        path = I18N_DIR / f"{lang}.json"
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error loading language file: {e}")
        # Fallback to English
        path = I18N_DIR / "en.json"
        return json.loads(path.read_text(encoding="utf-8"))

def make_layout(lang: str = "en") -> html.Div:
    """Create dashboard layout"""
    t = load_i18n(lang)
    direction = "rtl" if lang == "ar" else "ltr"
    font_family = "'Tajawal', 'Roboto', Tahoma, Arial, sans-serif" if lang == "ar" else "'Roboto', Tahoma, Arial, sans-serif"

    return html.Div(
        style={
            "direction": direction,
            "fontFamily": font_family,
            "padding": "16px",
            "backgroundColor": "#f8f9fa",
            "minHeight": "100vh"
        },
        children=[
            # Header
            html.Div(
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "backgroundColor": "#ffffff",
                    "padding": "20px",
                    "borderRadius": "10px",
                    "boxShadow": "0 4px 6px rgba(0,0,0,0.1)",
                    "marginBottom": "20px",
                    # ✅ Correct RTL/LTR border
                    "borderLeft": "5px solid #3498db" if lang == "en" else "none",
                    "borderRight": "5px solid #3498db" if lang == "ar" else "none",
                },
                children=[
                    html.Div(
                        children=[
                            html.H1(
                                t["app_title"],
                                style={
                                    "margin": 0,
                                    "color": "#2c3e50",
                                    "fontSize": "28px",
                                    "fontWeight": "bold"
                                }
                            ),
                            html.P(
                                "Enterprise Security Monitoring System v2.1.0",
                                style={
                                    "margin": "5px 0 0 0",
                                    "color": "#7f8c8d",
                                    "fontSize": "14px"
                                }
                            )
                        ]
                    ),
                    html.Div(
                        style={
                            "display": "flex",
                            "gap": "20px",
                            "alignItems": "center"
                        },
                        children=[
                            html.Div(
                                style={"display": "flex", "alignItems": "center", "gap": "10px"},
                                children=[
                                    html.I(className="fas fa-language", style={"color": "#3498db"}),
                                    dcc.Dropdown(
                                        id="lang",
                                        options=[
                                            {"label": "English", "value": "en"},
                                            {"label": "العربية", "value": "ar"}
                                        ],
                                        value=lang,
                                        clearable=False,
                                        style={"width": "150px", "minWidth": "150px"}
                                    ),
                                ]
                            ),
                            html.Div(
                                style={"display": "flex", "alignItems": "center", "gap": "10px"},
                                children=[
                                    html.I(className="fas fa-sync-alt", style={"color": "#3498db"}),
                                    dcc.Dropdown(
                                        id="refresh_seconds",
                                        options=[
                                            {"label": "5 seconds", "value": 5},
                                            {"label": "10 seconds", "value": 10},
                                            {"label": "30 seconds", "value": 30},
                                            {"label": "60 seconds", "value": 60},
                                        ],
                                        value=10,
                                        clearable=False,
                                        style={"width": "160px", "minWidth": "160px"}
                                    ),
                                ]
                            ),
                            html.Div(
                                style={
                                    "display": "flex",
                                    "alignItems": "center",
                                    "gap": "10px",
                                    "padding": "10px 15px",
                                    "backgroundColor": "#f8f9fa",
                                    "borderRadius": "5px",
                                    "border": "1px solid #e9ecef"
                                },
                                children=[
                                    html.I(className="fas fa-database", style={"color": "#27ae60"}),
                                    html.Span(
                                        "Live Database",
                                        style={
                                            "fontWeight": "bold",
                                            "color": "#27ae60",
                                            "fontSize": "14px"
                                        }
                                    )
                                ]
                            )
                        ]
                    ),
                ]
            ),

            # Tabs
            dcc.Tabs(
                id="tabs",
                value="overview",
                style={
                    "backgroundColor": "#ffffff",
                    "padding": "10px",
                    "borderRadius": "10px",
                    "boxShadow": "0 4px 6px rgba(0,0,0,0.1)",
                    "marginBottom": "20px"
                },
                children=[
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-tachometer-alt", style={"marginRight": "8px"}),
                            t["overview"]
                        ]),
                        value="overview",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-bell", style={"marginRight": "8px"}),
                            t["alerts"]
                        ]),
                        value="alerts",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-exclamation-triangle", style={"marginRight": "8px"}),
                            t["incidents"]
                        ]),
                        value="incidents",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-chart-line", style={"marginRight": "8px"}),
                            t["features"]
                        ]),
                        value="features",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-chart-bar", style={"marginRight": "8px"}),
                            t["charts"]
                        ]),
                        value="charts",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-list", style={"marginRight": "8px"}),
                            t["events"]
                        ]),
                        value="events",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-file-alt", style={"marginRight": "8px"}),
                            t["reports"]
                        ]),
                        value="reports",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-clipboard-check", style={"marginRight": "8px"}),
                            t.get("audit", "Audit")
                        ]),
                        value="audit",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                                        # ===== PHASE 3: AI TAB =====
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-brain", style={"marginRight": "8px"}),
                            t.get("ai", "AI Analytics")
                        ]),
                        value="ai",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                                        # ===== PHASE 5: INCIDENT DETAILS TAB =====
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-clipboard-list", style={"marginRight": "8px"}),
                            t.get("incident_details", "Incident Details")
                        ]),
                        value="incident_details",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                    
                    # ===== PHASE 5: KPIs TAB =====
                    dcc.Tab(
                        label=html.Span([
                            html.I(className="fas fa-chart-pie", style={"marginRight": "8px"}),
                            t.get("kpis", "KPIs")
                        ]),
                        value="kpis",
                        style={
                            "padding": "12px 20px",
                            "fontWeight": "bold",
                            "fontSize": "14px"
                        },
                        selected_style={
                            "backgroundColor": "#3498db",
                            "color": "white",
                            "borderBottom": "3px solid #2980b9"
                        }
                    ),
                ]
            ),

            # Interval for auto-refresh
            dcc.Interval(id="tick", interval=10000, n_intervals=0),

            # Page content
            html.Div(
                id="page",
                style={
                    "marginTop": "20px",
                    "backgroundColor": "#ffffff",
                    "padding": "25px",
                    "borderRadius": "10px",
                    "boxShadow": "0 4px 6px rgba(0,0,0,0.1)",
                    "minHeight": "500px"
                }
            ),

            # Footer
            html.Div(
                style={
                    "marginTop": "30px",
                    "textAlign": "center",
                    "color": "#7f8c8d",
                    "fontSize": "13px",
                    "padding": "15px",
                    "backgroundColor": "#ffffff",
                    "borderRadius": "10px",
                    "boxShadow": "0 4px 6px rgba(0,0,0,0.1)"
                },
                children=[
                    html.P([
                        "Security Monitoring System v2.1.0 | ",
                        html.Strong("Enterprise SOC Dashboard"),
                        " | ",
                        html.Span("🚀 Real-time monitoring and incident management", style={"color": "#3498db"})
                    ]),
                    html.P([
                        "© ",
                        html.Span(str(datetime.now().year), style={"color": "#e74c3c"}),
                        " | Developed with ",
                        html.I(className="fas fa-heart", style={"color": "#e74c3c"}),
                        " for cybersecurity professionals"
                    ]),
                    html.Div(
                        style={
                            "display": "flex",
                            "justifyContent": "center",
                            "gap": "20px",
                            "marginTop": "10px"
                        },
                        children=[
                            html.A(
                                html.I(className="fas fa-shield-alt"),
                                href="#",
                                style={"color": "#3498db", "textDecoration": "none"}
                            ),
                            html.A(
                                html.I(className="fas fa-code"),
                                href="#",
                                style={"color": "#3498db", "textDecoration": "none"}
                            ),
                            html.A(
                                html.I(className="fas fa-book"),
                                href="#",
                                style={"color": "#3498db", "textDecoration": "none"}
                            ),
                            html.A(
                                html.I(className="fas fa-cog"),
                                href="#",
                                style={"color": "#3498db", "textDecoration": "none"}
                            )
                        ]
                    )
                ]
            ),
        ]
    )