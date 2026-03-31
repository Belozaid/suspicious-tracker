# dashboard/components/controls.py
"""
Dashboard Control Components - Operational controls for SOC
Version 4.0.0
"""
from dash import html, dcc, dash_table
import plotly.graph_objs as go
from datetime import datetime

def create_incident_controls(incident_data: dict = None):
    """Create incident management controls"""
    
    severity_options = [
        {'label': '🔵 INFO', 'value': 'INFO'},
        {'label': '🟢 LOW', 'value': 'LOW'},
        {'label': '🟡 MEDIUM', 'value': 'MEDIUM'},
        {'label': '🟠 HIGH', 'value': 'HIGH'},
        {'label': '🔴 CRITICAL', 'value': 'CRITICAL'}
    ]
    
    status_options = [
        {'label': '🔵 OPEN', 'value': 'OPEN'},
        {'label': '🟣 INVESTIGATING', 'value': 'INVESTIGATING'},
        {'label': '🟠 CONTAINED', 'value': 'CONTAINED'},
        {'label': '🟢 RESOLVED', 'value': 'RESOLVED'},
        {'label': '⚫ FALSE_POSITIVE', 'value': 'FALSE_POSITIVE'}
    ]
    
    response_actions = [
        {'label': '📋 Create Report', 'value': 'create_report'},
        {'label': '📧 Send Notification', 'value': 'send_notification'},
        {'label': '🚨 Notify Team', 'value': 'notify_team'},
        {'label': '🔒 Isolate Host', 'value': 'isolate_host'},
        {'label': '🛡️ Block IP', 'value': 'block_ip'},
        {'label': '🧹 Quarantine File', 'value': 'quarantine_file'},
        {'label': '👁️ Elevate Monitoring', 'value': 'elevate_monitoring'},
        {'label': '🎫 Create Ticket', 'value': 'create_ticket'}
    ]
    
    return html.Div([
        html.H4("Incident Controls", style={'marginBottom': '20px'}),
        
        html.Div([
            # Status Update
            html.Div([
                html.Label("Update Status", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='status_update_dropdown',
                    options=status_options,
                    value=incident_data.get('status', 'OPEN') if incident_data else 'OPEN',
                    clearable=False,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                html.Button(
                    "Update Status",
                    id='update_status_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#3498db',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer'
                    }
                )
            ], style={'flex': '1', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px'}),
            
            # Severity Update
            html.Div([
                html.Label("Update Severity", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='severity_update_dropdown',
                    options=severity_options,
                    value=incident_data.get('max_severity', 'MEDIUM') if incident_data else 'MEDIUM',
                    clearable=False,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                html.Button(
                    "Update Severity",
                    id='update_severity_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#e74c3c',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer'
                    }
                )
            ], style={'flex': '1', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px', 'marginLeft': '15px'}),
            
            # Response Actions
            html.Div([
                html.Label("Response Actions", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='response_action_dropdown',
                    options=response_actions,
                    multi=True,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                html.Div([
                    html.Button(
                        "Execute Actions",
                        id='execute_actions_btn',
                        n_clicks=0,
                        style={
                            'flex': '1',
                            'padding': '10px',
                            'backgroundColor': '#2ecc71',
                            'color': 'white',
                            'border': 'none',
                            'borderRadius': '5px',
                            'cursor': 'pointer',
                            'marginRight': '5px'
                        }
                    ),
                    dcc.Checklist(
                        id='require_approval_check',
                        options=[{'label': 'Require Approval', 'value': 'require'}],
                        value=[],
                        style={'flex': '1', 'marginLeft': '5px'}
                    )
                ], style={'display': 'flex', 'alignItems': 'center'})
            ], style={'flex': '2', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px', 'marginLeft': '15px'})
        ], style={'display': 'flex', 'marginBottom': '20px'}),
        
        # Action History
        html.Div([
            html.H5("Recent Actions", style={'marginBottom': '10px'}),
            html.Div(id='action_history_container', style={
                'maxHeight': '200px',
                'overflowY': 'auto',
                'padding': '10px',
                'backgroundColor': 'white',
                'borderRadius': '5px',
                'border': '1px solid #ddd'
            })
        ])
    ])

def create_report_controls():
    """Create report generation controls"""
    
    report_types = [
        {'label': '📋 Incident Report', 'value': 'incident'},
        {'label': '📊 Executive Summary', 'value': 'executive'},
        {'label': '📈 Trend Analysis', 'value': 'trend'},
        {'label': '🛡️ Compliance Report', 'value': 'compliance'},
        {'label': '🔍 Forensic Report', 'value': 'forensic'}
    ]
    
    formats = [
        {'label': 'PDF Document', 'value': 'pdf'},
        {'label': 'HTML Report', 'value': 'html'},
        {'label': 'JSON Data', 'value': 'json'},
        {'label': 'CSV Export', 'value': 'csv'}
    ]
    
    return html.Div([
        html.H4("Report Generation", style={'marginBottom': '20px'}),
        
        html.Div([
            # Report Configuration
            html.Div([
                html.Label("Report Type", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='report_type_dropdown',
                    options=report_types,
                    value='incident',
                    clearable=False,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                
                html.Label("Format", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='report_format_dropdown',
                    options=formats,
                    value='pdf',
                    clearable=False,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                
                dcc.Checklist(
                    id='report_options_checklist',
                    options=[
                        {'label': 'Include Evidence', 'value': 'evidence'},
                        {'label': 'Include Screenshots', 'value': 'screenshots'},
                        {'label': 'Include Recommendations', 'value': 'recommendations'},
                        {'label': 'Include MITRE Mapping', 'value': 'mitre'}
                    ],
                    value=['evidence', 'recommendations'],
                    style={'marginBottom': '15px'}
                ),
                
                html.Label("Time Range", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.DatePickerRange(
                    id='report_date_range',
                    start_date=datetime.now().date(),
                    end_date=datetime.now().date(),
                    display_format='YYYY-MM-DD',
                    style={'width': '100%', 'marginBottom': '15px'}
                )
            ], style={'flex': '1', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px'}),
            
            # Report Preview & Actions
            html.Div([
                html.Label("Report Preview", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                html.Div(id='report_preview', style={
                    'height': '200px',
                    'overflowY': 'auto',
                    'padding': '10px',
                    'backgroundColor': 'white',
                    'borderRadius': '5px',
                    'border': '1px solid #ddd',
                    'marginBottom': '15px',
                    'fontFamily': 'monospace',
                    'fontSize': '12px'
                }),
                
                html.Div([
                    html.Button(
                        "📄 Generate Report",
                        id='generate_report_btn',
                        n_clicks=0,
                        style={
                            'flex': '1',
                            'padding': '10px',
                            'backgroundColor': '#3498db',
                            'color': 'white',
                            'border': 'none',
                            'borderRadius': '5px',
                            'cursor': 'pointer',
                            'marginRight': '5px'
                        }
                    ),
                    html.Button(
                        "📥 Download All",
                        id='download_reports_btn',
                        n_clicks=0,
                        style={
                            'flex': '1',
                            'padding': '10px',
                            'backgroundColor': '#2ecc71',
                            'color': 'white',
                            'border': 'none',
                            'borderRadius': '5px',
                            'cursor': 'pointer',
                            'marginLeft': '5px'
                        }
                    )
                ], style={'display': 'flex'})
            ], style={'flex': '1', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px', 'marginLeft': '15px'})
        ], style={'display': 'flex', 'marginBottom': '20px'}),
        
        # Available Reports
        html.Div([
            html.H5("Available Reports", style={'marginBottom': '10px'}),
            dash_table.DataTable(
                id='reports_table',
                columns=[
                    {'name': 'Filename', 'id': 'filename'},
                    {'name': 'Type', 'id': 'type'},
                    {'name': 'Size', 'id': 'size'},
                    {'name': 'Created', 'id': 'created'},
                    {'name': 'Actions', 'id': 'actions'}
                ],
                data=[],
                page_size=5,
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '10px',
                    'whiteSpace': 'normal'
                },
                style_header={
                    'backgroundColor': '#34495e',
                    'color': 'white',
                    'fontWeight': 'bold'
                }
            )
        ])
    ])

def create_audit_controls():
    """Create audit trail controls"""
    
    return html.Div([
        html.H4("Audit Trail", style={'marginBottom': '20px'}),
        
        html.Div([
            # Filters
            html.Div([
                html.Label("Time Range", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.DatePickerRange(
                    id='audit_date_range',
                    start_date=datetime.now().date(),
                    end_date=datetime.now().date(),
                    display_format='YYYY-MM-DD',
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                
                html.Label("Action Type", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='audit_action_filter',
                    options=[
                        {'label': 'All Actions', 'value': 'all'},
                        {'label': 'Login/Logout', 'value': 'auth'},
                        {'label': 'Configuration Changes', 'value': 'config'},
                        {'label': 'Incident Operations', 'value': 'incident'},
                        {'label': 'Report Operations', 'value': 'report'}
                    ],
                    value='all',
                    clearable=False,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                
                html.Label("User", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='audit_user_filter',
                    options=[],
                    multi=True,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                
                html.Div([
                    html.Button(
                        "🔍 Apply Filters",
                        id='apply_audit_filters',
                        n_clicks=0,
                        style={
                            'flex': '1',
                            'padding': '10px',
                            'backgroundColor': '#3498db',
                            'color': 'white',
                            'border': 'none',
                            'borderRadius': '5px',
                            'cursor': 'pointer',
                            'marginRight': '5px'
                        }
                    ),
                    html.Button(
                        "📊 Generate Audit Report",
                        id='generate_audit_report',
                        n_clicks=0,
                        style={
                            'flex': '1',
                            'padding': '10px',
                            'backgroundColor': '#9b59b6',
                            'color': 'white',
                            'border': 'none',
                            'borderRadius': '5px',
                            'cursor': 'pointer',
                            'marginLeft': '5px'
                        }
                    )
                ], style={'display': 'flex'})
            ], style={'flex': '1', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px'}),
            
            # Statistics
            html.Div([
                html.Label("Audit Statistics", style={'fontWeight': 'bold', 'marginBottom': '15px'}),
                html.Div([
                    html.Div([
                        html.Div("0", id='total_audit_events', style={
                            'fontSize': '24px',
                            'fontWeight': 'bold',
                            'color': '#2c3e50'
                        }),
                        html.Div("Total Events", style={
                            'fontSize': '12px',
                            'color': '#7f8c8d'
                        })
                    ], style={'textAlign': 'center', 'padding': '10px', 'backgroundColor': 'white', 'borderRadius': '5px', 'margin': '5px'}),
                    
                    html.Div([
                        html.Div("0", id='unique_users_count', style={
                            'fontSize': '24px',
                            'fontWeight': 'bold',
                            'color': '#3498db'
                        }),
                        html.Div("Unique Users", style={
                            'fontSize': '12px',
                            'color': '#7f8c8d'
                        })
                    ], style={'textAlign': 'center', 'padding': '10px', 'backgroundColor': 'white', 'borderRadius': '5px', 'margin': '5px'}),
                    
                    html.Div([
                        html.Div("0", id='failed_actions_count', style={
                            'fontSize': '24px',
                            'fontWeight': 'bold',
                            'color': '#e74c3c'
                        }),
                        html.Div("Failed Actions", style={
                            'fontSize': '12px',
                            'color': '#7f8c8d'
                        })
                    ], style={'textAlign': 'center', 'padding': '10px', 'backgroundColor': 'white', 'borderRadius': '5px', 'margin': '5px'}),
                    
                    html.Div([
                        html.Div("0", id='system_changes_count', style={
                            'fontSize': '24px',
                            'fontWeight': 'bold',
                            'color': '#f39c12'
                        }),
                        html.Div("System Changes", style={
                            'fontSize': '12px',
                            'color': '#7f8c8d'
                        })
                    ], style={'textAlign': 'center', 'padding': '10px', 'backgroundColor': 'white', 'borderRadius': '5px', 'margin': '5px'})
                ], style={'display': 'grid', 'gridTemplateColumns': 'repeat(2, 1fr)', 'gap': '10px'})
            ], style={'flex': '1', 'padding': '15px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px', 'marginLeft': '15px'})
        ], style={'display': 'flex', 'marginBottom': '20px'}),
        
        # Audit Log Table
        html.Div([
            html.H5("Audit Log", style={'marginBottom': '10px'}),
            dash_table.DataTable(
                id='audit_log_table',
                columns=[
                    {'name': 'Timestamp', 'id': 'timestamp'},
                    {'name': 'User', 'id': 'user_id'},
                    {'name': 'Action', 'id': 'action_type'},
                    {'name': 'Resource', 'id': 'resource_type'},
                    {'name': 'Status', 'id': 'status'},
                    {'name': 'Details', 'id': 'details'}
                ],
                data=[],
                page_size=10,
                style_table={'overflowX': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '10px',
                    'whiteSpace': 'normal',
                    'maxWidth': '200px',
                    'overflow': 'hidden',
                    'textOverflow': 'ellipsis'
                },
                style_header={
                    'backgroundColor': '#34495e',
                    'color': 'white',
                    'fontWeight': 'bold'
                },
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{status} = "FAILURE"'},
                        'backgroundColor': '#ffebee',
                        'color': '#c62828'
                    },
                    {
                        'if': {'filter_query': '{status} = "PENDING"'},
                        'backgroundColor': '#fff3e0',
                        'color': '#ef6c00'
                    }
                ],
                tooltip_data=[],
                tooltip_duration=None
            )
        ])
    ])

def create_system_controls():
    """Create system configuration controls"""
    
    response_policies = [
        {'label': '🛡️ Aggressive - Maximum automation', 'value': 'aggressive'},
        {'label': '⚖️ Balanced - Mixed automation/manual', 'value': 'balanced'},
        {'label': '🕊️ Conservative - Manual approval required', 'value': 'conservative'},
        {'label': '👁️ Monitor Only - No automated actions', 'value': 'monitor_only'}
    ]
    
    notification_channels = [
        {'label': '🔔 Desktop Notifications', 'value': 'desktop'},
        {'label': '📧 Email Alerts', 'value': 'email'},
        {'label': '🔊 Sound Alerts', 'value': 'sound'},
        {'label': '📱 Mobile Notifications', 'value': 'mobile'}
    ]
    
    return html.Div([
        html.H4("System Configuration", style={'marginBottom': '20px'}),
        
        html.Div([
            # Response Policies
            html.Div([
                html.H5("Response Policies", style={'marginBottom': '15px'}),
                
                html.Label("Automation Level", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Dropdown(
                    id='response_policy_dropdown',
                    options=response_policies,
                    value='balanced',
                    clearable=False,
                    style={'width': '100%', 'marginBottom': '15px'}
                ),
                
                html.Label("Auto-response Triggers", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Checklist(
                    id='auto_response_triggers',
                    options=[
                        {'label': '🟢 Enable for LOW severity', 'value': 'low'},
                        {'label': '🟡 Enable for MEDIUM severity', 'value': 'medium'},
                        {'label': '🟠 Enable for HIGH severity', 'value': 'high'},
                        {'label': '🔴 Enable for CRITICAL severity', 'value': 'critical'}
                    ],
                    value=['high', 'critical'],
                    style={'marginBottom': '15px'}
                ),
                
                html.Label("Approval Requirements", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Checklist(
                    id='approval_requirements',
                    options=[
                        {'label': 'Require approval for host isolation', 'value': 'isolate'},
                        {'label': 'Require approval for IP blocking', 'value': 'block'},
                        {'label': 'Require approval for file quarantine', 'value': 'quarantine'},
                        {'label': 'Require approval for user suspension', 'value': 'suspend'}
                    ],
                    value=['isolate', 'block', 'quarantine'],
                    style={'marginBottom': '15px'}
                ),
                
                html.Button(
                    "💾 Save Response Policy",
                    id='save_response_policy',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#2ecc71',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer'
                    }
                )
            ], style={'flex': '1', 'padding': '20px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px'}),
            
            # Notification Settings
            html.Div([
                html.H5("Notification Settings", style={'marginBottom': '15px'}),
                
                html.Label("Notification Channels", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Checklist(
                    id='notification_channels',
                    options=notification_channels,
                    value=['desktop', 'sound'],
                    style={'marginBottom': '15px'}
                ),
                
                html.Label("Alert Thresholds", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                html.Div([
                    html.Label("Email notifications for:", style={'fontSize': '14px', 'marginBottom': '5px'}),
                    dcc.Checklist(
                        id='email_thresholds',
                        options=[
                            {'label': 'CRITICAL incidents', 'value': 'critical'},
                            {'label': 'HIGH incidents', 'value': 'high'},
                            {'label': 'MEDIUM incidents', 'value': 'medium'}
                        ],
                        value=['critical', 'high'],
                        style={'marginBottom': '15px'}
                    )
                ]),
                
                html.Label("Sound Alerts", style={'fontWeight': 'bold', 'marginBottom': '5px'}),
                dcc.Slider(
                    id='sound_volume_slider',
                    min=0,
                    max=100,
                    step=10,
                    value=50,
                    marks={i: f'{i}%' for i in range(0, 101, 20)},
                    style={'marginBottom': '15px'}
                ),
                
                html.Button(
                    "🔔 Test Notifications",
                    id='test_notifications',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#3498db',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer'
                    }
                )
            ], style={'flex': '1', 'padding': '20px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px', 'marginLeft': '20px'}),
            
            # System Actions
            html.Div([
                html.H5("System Actions", style={'marginBottom': '15px'}),
                
                html.Button(
                    "🔄 Clear Cache",
                    id='clear_cache_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#f39c12',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer',
                        'marginBottom': '10px'
                    }
                ),
                
                html.Button(
                    "📊 Database Maintenance",
                    id='db_maintenance_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#9b59b6',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer',
                        'marginBottom': '10px'
                    }
                ),
                
                html.Button(
                    "📈 Generate System Report",
                    id='system_report_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#1abc9c',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer',
                        'marginBottom': '10px'
                    }
                ),
                
                html.Button(
                    "🛡️ Backup Configuration",
                    id='backup_config_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#34495e',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer',
                        'marginBottom': '10px'
                    }
                ),
                
                html.Button(
                    "⚠️ Emergency Stop",
                    id='emergency_stop_btn',
                    n_clicks=0,
                    style={
                        'width': '100%',
                        'padding': '10px',
                        'backgroundColor': '#e74c3c',
                        'color': 'white',
                        'border': 'none',
                        'borderRadius': '5px',
                        'cursor': 'pointer',
                        'marginBottom': '10px'
                    }
                )
            ], style={'flex': '1', 'padding': '20px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px', 'marginLeft': '20px'})
        ], style={'display': 'flex', 'marginBottom': '20px'}),
        
        # System Status
        html.Div([
            html.H5("System Status", style={'marginBottom': '10px'}),
            html.Div(id='system_status_display', style={
                'padding': '15px',
                'backgroundColor': 'white',
                'borderRadius': '5px',
                'border': '1px solid #ddd',
                'fontFamily': 'monospace',
                'fontSize': '12px'
            })
        ])
    ])