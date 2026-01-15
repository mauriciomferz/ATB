                                                                                                                                        #!/usr/bin/env python3
"""Generate ATB Documentation PDF"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, ListFlowable, ListItem
)
from reportlab.lib import colors
from datetime import datetime

def create_pdf():
    doc = SimpleDocTemplate(
        "ATB_Documentation.pdf",
        pagesize=letter,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        textColor=HexColor('#1a365d')
    )
    
    h1_style = ParagraphStyle(
        'CustomH1',
        parent=styles['Heading1'],
        fontSize=20,
        spaceBefore=20,
        spaceAfter=12,
        textColor=HexColor('#2c5282')
    )
    
    h2_style = ParagraphStyle(
        'CustomH2',
        parent=styles['Heading2'],
        fontSize=16,
        spaceBefore=16,
        spaceAfter=10,
        textColor=HexColor('#2b6cb0')
    )
    
    h3_style = ParagraphStyle(
        'CustomH3',
        parent=styles['Heading3'],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=8,
        textColor=HexColor('#3182ce')
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=8,
        leading=14
    )
    
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        backColor=HexColor('#f7fafc'),
        leftIndent=10,
        rightIndent=10,
        spaceAfter=10,
        leading=12
    )
    
    story = []
    
    # ============ TITLE PAGE ============
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("Agent Trust Broker (ATB)", title_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Documentation Guide", styles['Heading2']))
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y')}", body_style))
    story.append(Paragraph("Version: 0.1.0", body_style))
    story.append(PageBreak())
    
    # ============ TABLE OF CONTENTS ============
    story.append(Paragraph("Table of Contents", h1_style))
    story.append(Spacer(1, 0.2*inch))
    
    toc_items = [
        "1. Overview",
        "2. Architecture",
        "3. Key Features",
        "4. Components",
        "5. Proof-of-Authorization (PoA)",
        "6. Risk Tiers",
        "7. Authentication Flow",
        "8. SPIFFE/SPIRE Identity",
        "9. API Reference",
        "10. Configuration",
        "11. Security Best Practices",
        "12. Frequently Asked Questions",
        "13. Troubleshooting",
    ]
    for item in toc_items:
        story.append(Paragraph(item, body_style))
    story.append(PageBreak())
    
    # ============ OVERVIEW ============
    story.append(Paragraph("1. Overview", h1_style))
    story.append(Paragraph(
        "ATB (Agent Trust Broker) is a security enforcement layer for enterprise AI agent deployments, "
        "implementing the AI Safe Enterprise Autonomy Architecture.",
        body_style
    ))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(
        "ATB provides a single enforcement boundary between AI agent platforms and enterprise systems. "
        "Every agent action is:",
        body_style
    ))
    
    bullet_items = [
        "<b>Authenticated</b> via SPIFFE/SPIRE workload identity",
        "<b>Authorized</b> via signed Proof-of-Authorization (PoA) mandates",
        "<b>Constrained</b> by OPA policy with risk-tiered controls",
        "<b>Audited</b> with immutable, tamper-evident logs"
    ]
    for item in bullet_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    # ============ ARCHITECTURE ============
    story.append(Paragraph("2. Architecture", h1_style))
    story.append(Paragraph(
        "ATB is an enterprise security enforcement layer that validates AI agent actions before "
        "they execute on backend systems. It implements a Proof-of-Authorization (PoA) framework "
        "with risk-tiered governance.",
        body_style
    ))
    
    story.append(Paragraph("Request Flow", h2_style))
    flow_steps = [
        "1. Agent → Broker: mTLS with SPIFFE cert + PoA token",
        "2. Broker extracts SPIFFE ID and validates PoA JWT signature",
        "3. Broker → OPA: Policy decision request",
        "4. If allowed: Broker → Upstream: Proxy request + Audit log",
        "5. If denied: Broker → Agent: 403 + denial reasons + Audit log"
    ]
    for step in flow_steps:
        story.append(Paragraph(step, body_style))
    
    # ============ KEY FEATURES ============
    story.append(Paragraph("3. Key Features", h1_style))
    
    features_data = [
        ['Feature', 'Description'],
        ['SPIFFE/SPIRE Identity', 'X509-SVID for mTLS, JWT-SVID for external APIs'],
        ['PoA Mandates', 'Short-lived, signed authorization tokens with act/con/leg claims'],
        ['Risk-Tiered Policy', '145+ enterprise actions across low/medium/high risk tiers'],
        ['Dual Control', 'High-risk actions require two distinct approvers'],
        ['Semantic Guardrails', 'Prompt injection detection with external service support'],
        ['Immutable Audit', 'Azure Blob/S3 Object Lock with hash-chain tamper evidence'],
        ['Platform Binding', 'OIDC platform tokens bound to SPIFFE identities'],
    ]
    
    features_table = Table(features_data, colWidths=[2*inch, 4*inch])
    features_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(features_table)
    
    # ============ COMPONENTS ============
    story.append(Paragraph("4. Components", h1_style))
    
    components_data = [
        ['Component', 'Description'],
        ['atb-broker', 'Main enforcement gateway (Go)'],
        ['atb-agentauth', 'PoA issuance service with dual-control support'],
        ['opa', 'Policy decision engine (sidecar)'],
        ['spire-agent', 'SPIFFE workload identity'],
    ]
    
    components_table = Table(components_data, colWidths=[2*inch, 4*inch])
    components_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(components_table)
    
    story.append(Paragraph("ATB Broker", h3_style))
    story.append(Paragraph("The broker is the core gateway that:", body_style))
    broker_items = [
        "Terminates mTLS connections from AI agents",
        "Extracts SPIFFE IDs from client certificates",
        "Validates PoA tokens (RS256 JWT mandates)",
        "Queries OPA for policy decisions",
        "Proxies authorized requests to upstream backends",
        "Emits audit events for compliance"
    ]
    for item in broker_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    story.append(Paragraph("AgentAuth Service", h3_style))
    story.append(Paragraph("Issues PoA tokens to authorized agents:", body_style))
    auth_items = [
        "Validates agent identity via mTLS/SPIFFE",
        "Mints short-lived PoA JWTs with action scope",
        "Enforces platform-specific constraints",
        "Supports risk-tier approval requirements"
    ]
    for item in auth_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    # ============ POA TOKENS ============
    story.append(PageBreak())
    story.append(Paragraph("5. Proof-of-Authorization (PoA)", h1_style))
    story.append(Paragraph(
        "PoA tokens are short-lived, signed JWTs that authorize specific actions. "
        "They are the core authorization mechanism in ATB.",
        body_style
    ))
    
    story.append(Paragraph("PoA Token Structure", h2_style))
    story.append(Paragraph(
        "A PoA token is a signed JWT mandate that authorizes a specific action:",
        body_style
    ))
    
    poa_example = """
{
  "sub": "spiffe://example.org/agent/demo",
  "act": "crm.contact.update",
  "con": {
    "max_records": 10,
    "allowed_fields": ["name", "email"]
  },
  "leg": {
    "basis": "contract",
    "jurisdiction": "US",
    "accountable_party": {
      "type": "human",
      "id": "user@example.com"
    }
  },
  "iat": 1736679600,
  "exp": 1736679900,
  "jti": "poa_abc123xyz"
}
"""
    story.append(Paragraph(poa_example.replace('\n', '<br/>'), code_style))
    
    story.append(Paragraph("PoA Claims", h2_style))
    claims_data = [
        ['Claim', 'Required', 'Description'],
        ['sub', 'Yes', "Subject (agent's SPIFFE ID)"],
        ['act', 'Yes', 'Action being authorized'],
        ['con', 'No', 'Constraints (limits, filters)'],
        ['leg', 'Yes', 'Legal basis for the action'],
        ['iat', 'Yes', 'Issued at (Unix timestamp)'],
        ['exp', 'Yes', 'Expiration (Unix timestamp)'],
        ['jti', 'Yes', 'Unique token ID (replay protection)'],
    ]
    
    claims_table = Table(claims_data, colWidths=[1*inch, 1*inch, 4*inch])
    claims_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(claims_table)
    
    story.append(Paragraph("Legal Basis (leg)", h3_style))
    story.append(Paragraph(
        "Every PoA must include a legal basis explaining why the action is permitted:",
        body_style
    ))
    leg_items = [
        "<b>basis</b>: contract, consent, legitimate_interest, legal_obligation",
        "<b>ref</b>: Reference to legal document (e.g., MSA-2026-001)",
        "<b>jurisdiction</b>: Legal jurisdiction (e.g., US, DE, UK)",
        "<b>accountable_party</b>: Who is accountable (human or organization)"
    ]
    for item in leg_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    story.append(Paragraph("Constraints (con)", h3_style))
    story.append(Paragraph("Constraints limit what the action can do:", body_style))
    con_items = [
        "max_amount, currency - Financial limits",
        "allowed_vendors - Vendor allowlists",
        "max_records - Record count limits",
        "exclude_fields - PII field exclusions"
    ]
    for item in con_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    # ============ RISK TIERS ============
    story.append(Paragraph("6. Risk Tiers", h1_style))
    story.append(Paragraph(
        "ATB enforces three risk tiers based on the action being performed:",
        body_style
    ))
    
    risk_data = [
        ['Tier', 'Actions', 'Approval', 'Examples'],
        ['HIGH', '60+', 'Dual control (2 approvers)', 'SAP payments, PII export, IAM escalation'],
        ['MEDIUM', '40+', 'Single approver', 'CRM updates, order management'],
        ['LOW', '45+', 'PoA only', 'Read operations, status checks'],
    ]
    
    risk_table = Table(risk_data, colWidths=[1*inch, 0.8*inch, 1.8*inch, 2.4*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (0, 1), HexColor('#fc8181')),  # HIGH - red
        ('BACKGROUND', (0, 2), (0, 2), HexColor('#f6e05e')),  # MEDIUM - yellow
        ('BACKGROUND', (0, 3), (0, 3), HexColor('#68d391')),  # LOW - green
        ('BACKGROUND', (1, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(risk_table)
    
    story.append(Paragraph("Dual Control Rules (High Risk)", h3_style))
    dual_items = [
        "Two approvers must be <b>distinct</b> (different approver_id)",
        "The <b>requester</b> cannot be an approver",
        "Both approvals must happen before the challenge expires",
        "Approval order doesn't matter"
    ]
    for item in dual_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    # ============ AUTHENTICATION FLOW ============
    story.append(PageBreak())
    story.append(Paragraph("7. Authentication Flow", h1_style))
    story.append(Paragraph(
        "ATB uses a zero-trust model where every action must be explicitly authorized:",
        body_style
    ))
    
    flow_steps = [
        "<b>Step 1:</b> Agent requests a challenge from AgentAuth (POST /v1/challenge)",
        "<b>Step 2:</b> Approvals collected based on risk tier",
        "<b>Step 3:</b> AgentAuth issues PoA token after approvals",
        "<b>Step 4:</b> Agent calls Broker with X-Poa-Token header",
        "<b>Step 5:</b> Broker validates token and proxies to upstream"
    ]
    for step in flow_steps:
        story.append(Paragraph(step, body_style))
    
    story.append(Paragraph("Medium-Risk Flow (Single Approval)", h2_style))
    medium_flow = """
# 1. Create challenge
POST /v1/challenge
{ "action": "crm.contact.update", ... }

# 2. Submit approval
POST /v1/challenge/{id}/approve
{ "approver_id": "manager@example.com" }

# 3. Get PoA token in response
{ "poa": "eyJhbGciOiJSUzI1NiI..." }
"""
    story.append(Paragraph(medium_flow.replace('\n', '<br/>'), code_style))
    
    story.append(Paragraph("High-Risk Flow (Dual Control)", h2_style))
    high_flow = """
# 1. Create challenge (requires 2 approvers)
POST /v1/challenge
{ "action": "sap.payment.execute", ... }

# 2. First approval
POST /v1/challenge/{id}/approve
{ "approver_id": "finance-manager@example.com" }

# 3. Second approval (different person!)
POST /v1/challenge/{id}/approve  
{ "approver_id": "cfo@example.com" }

# 4. PoA token issued after both approvals
"""
    story.append(Paragraph(high_flow.replace('\n', '<br/>'), code_style))
    
    # ============ SPIFFE/SPIRE ============
    story.append(Paragraph("8. SPIFFE/SPIRE Identity", h1_style))
    story.append(Paragraph(
        "Every workload in ATB has a cryptographic identity via SPIFFE (Secure Production "
        "Identity Framework for Everyone).",
        body_style
    ))
    
    story.append(Paragraph("SPIFFE ID Format", h2_style))
    story.append(Paragraph("spiffe://&lt;trust-domain&gt;/&lt;workload-path&gt;", code_style))
    story.append(Paragraph("Examples:", body_style))
    spiffe_examples = [
        "spiffe://prod.company.com/ns/agents/sa/claude-assistant",
        "spiffe://prod.company.com/ns/connectors/sa/sap-connector"
    ]
    for ex in spiffe_examples:
        story.append(Paragraph(f"• {ex}", body_style))
    
    story.append(Paragraph("How Identity Works", h2_style))
    identity_steps = [
        "<b>SPIRE Agent</b> runs on each node",
        "<b>Workloads</b> request SVIDs (SPIFFE Verifiable Identity Documents)",
        "<b>X.509-SVID</b> used for mTLS connections",
        "<b>JWT-SVID</b> can be used for API authentication"
    ]
    for step in identity_steps:
        story.append(Paragraph(f"• {step}", body_style))
    
    # ============ API REFERENCE ============
    story.append(Paragraph("9. API Reference", h1_style))
    
    api_data = [
        ['Endpoint', 'Method', 'Service', 'Purpose'],
        ['/health', 'GET', 'Both', 'Health check'],
        ['/authorize', 'POST', 'AgentAuth', 'Request PoA token (low-risk)'],
        ['/challenge', 'POST', 'AgentAuth', 'Create approval challenge'],
        ['/challenge/{id}/approve', 'POST', 'AgentAuth', 'Submit approval'],
        ['/challenge/{id}/complete', 'POST', 'AgentAuth', 'Get PoA after approval'],
        ['/*', 'ANY', 'Broker', 'Proxy to upstream with PoA validation'],
    ]
    
    api_table = Table(api_data, colWidths=[2*inch, 0.8*inch, 1.2*inch, 2*inch])
    api_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(api_table)
    
    story.append(Paragraph("Headers", h2_style))
    headers_data = [
        ['Header', 'Required', 'Description'],
        ['X-Poa-Token', 'Yes (Broker)', 'Signed PoA JWT token'],
        ['X-Request-Id', 'No', 'Correlation ID for tracing'],
        ['Authorization', 'Alt', 'Bearer token (alternative to X-Poa-Token)'],
    ]
    
    headers_table = Table(headers_data, colWidths=[1.5*inch, 1.5*inch, 3*inch])
    headers_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(headers_table)
    
    # ============ CONFIGURATION ============
    story.append(PageBreak())
    story.append(Paragraph("10. Configuration", h1_style))
    
    story.append(Paragraph("Environment Variables (Broker)", h2_style))
    
    env_data = [
        ['Variable', 'Default', 'Description'],
        ['SPIFFE_ENDPOINT_SOCKET', '/run/spire/sockets/agent.sock', 'SPIRE Workload API socket'],
        ['OPA_DECISION_URL', 'http://localhost:8181/...', 'OPA policy endpoint'],
        ['POA_SINGLE_USE', 'true', 'Enable PoA replay protection'],
        ['ALLOW_UNMANDATED_LOW_RISK', 'false', 'Allow low-risk without PoA'],
        ['GUARDRAILS_URL', '-', 'External guardrails service'],
        ['AUDIT_SINK_URL', '-', 'Audit event sink endpoint'],
    ]
    
    env_table = Table(env_data, colWidths=[2.2*inch, 1.8*inch, 2*inch])
    env_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(env_table)
    
    story.append(Paragraph("Quick Start", h2_style))
    story.append(Paragraph("Deploy with Helm:", body_style))
    helm_cmd = """
helm install atb charts/atb \\
  -n atb \\
  -f charts/atb/values-staging.yaml \\
  -f charts/atb/values-observability.yaml
"""
    story.append(Paragraph(helm_cmd.replace('\n', '<br/>'), code_style))
    
    story.append(Paragraph("Docker Compose (Development):", body_style))
    docker_cmd = """
make docker-up

# Services:
#   OPA:        http://localhost:8181
#   Upstream:   http://localhost:9000  
#   Broker:     https://localhost:8443 (mTLS)
#   AgentAuth:  http://localhost:8444
"""
    story.append(Paragraph(docker_cmd.replace('\n', '<br/>'), code_style))
    
    # ============ SECURITY BEST PRACTICES ============
    story.append(Paragraph("11. Security Best Practices", h1_style))
    story.append(Paragraph(
        "ATB implements multiple layers of security (defense in depth):",
        body_style
    ))
    
    security_layers = [
        "<b>Network Layer:</b> mTLS, Egress Allowlist, Network Policies",
        "<b>Identity Layer:</b> SPIFFE/SPIRE, X.509 SVIDs, Certificate Rotation",
        "<b>Authorization Layer:</b> PoA Tokens, OPA Policy, Risk Tiers",
        "<b>Audit Layer:</b> Immutable Logs, Hash Chain, Tamper Evidence"
    ]
    for layer in security_layers:
        story.append(Paragraph(f"• {layer}", body_style))
    
    story.append(Paragraph("Token Lifetimes", h2_style))
    ttl_data = [
        ['Token Type', 'Recommended TTL', 'Rationale'],
        ['Low-risk actions', '5 minutes', 'Short window of opportunity'],
        ['Medium-risk actions', '3 minutes', 'Reduced exposure'],
        ['High-risk actions', '1 minute', 'Minimize risk window'],
        ['Challenge tokens', '5 minutes', 'Time for approval flow'],
    ]
    
    ttl_table = Table(ttl_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
    ttl_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(ttl_table)
    
    story.append(Paragraph("Key Rotation Schedule", h2_style))
    key_data = [
        ['Key Type', 'Rotation Period', 'Notes'],
        ['Signing keys', '90 days', 'Overlap period for validation'],
        ['mTLS certificates', '24 hours', 'Automatic via SPIRE'],
        ['HSM master keys', 'Annual', 'Requires maintenance window'],
    ]
    
    key_table = Table(key_data, colWidths=[2*inch, 1.5*inch, 2.5*inch])
    key_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(key_table)
    
    story.append(Paragraph("Identity Best Practices", h2_style))
    identity_tips = [
        "Use <b>unique identities</b> per agent instance",
        "Include <b>environment</b> in identity (prod/staging/dev)",
        "Use <b>separate trust domains</b> for environments",
        "Limit identity scope - minimum needed",
        "Configure <b>short-lived certificates</b> (1h SVID TTL)"
    ]
    for tip in identity_tips:
        story.append(Paragraph(f"• {tip}", body_style))
    
    # ============ FAQ ============
    story.append(PageBreak())
    story.append(Paragraph("12. Frequently Asked Questions", h1_style))
    
    story.append(Paragraph("What is ATB?", h3_style))
    story.append(Paragraph(
        "ATB (Agent Trust Broker) is a security gateway that controls what AI agents can do in "
        "enterprise environments. It ensures every agent action is authenticated, authorized, and audited.",
        body_style
    ))
    
    story.append(Paragraph("Why do I need ATB?", h3_style))
    story.append(Paragraph(
        "When AI agents interact with enterprise systems (SAP, Salesforce, databases, etc.), you need:",
        body_style
    ))
    why_items = [
        "<b>Access control:</b> Limit what agents can do",
        "<b>Approval workflows:</b> Human oversight for sensitive actions",
        "<b>Audit trails:</b> Know who did what and why",
        "<b>Compliance:</b> Meet GDPR, SOX, and other regulations"
    ]
    for item in why_items:
        story.append(Paragraph(f"• {item}", body_style))
    
    story.append(Paragraph("How is ATB different from regular API gateways?", h3_style))
    diff_data = [
        ['Feature', 'API Gateway', 'ATB'],
        ['Authentication', 'API keys, OAuth', 'SPIFFE workload identity'],
        ['Authorization', 'Role-based (RBAC)', 'Action-based with constraints'],
        ['Approval flows', 'None', 'Built-in human-in-the-loop'],
        ['Risk tiers', 'None', 'Low/Medium/High with escalation'],
        ['Legal basis', 'None', 'Required for compliance'],
        ['Dual control', 'None', 'Built-in for high-risk'],
    ]
    
    diff_table = Table(diff_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
    diff_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(diff_table)
    
    story.append(Paragraph("What AI platforms work with ATB?", h3_style))
    story.append(Paragraph(
        "ATB is platform-agnostic. It works with OpenAI/GPT, Anthropic Claude, Microsoft Copilot, "
        "LangChain agents, and custom frameworks. The agent just needs to obtain a SPIFFE identity, "
        "request PoA tokens, and include them in requests.",
        body_style
    ))
    
    story.append(Paragraph("Can I customize risk tiers?", h3_style))
    story.append(Paragraph(
        "Yes! Edit opa/policy/poa.rego to add custom actions to risk tier sets or change existing "
        "action classifications. You can also implement dynamic risk based on constraints (e.g., "
        "payment amount determines tier).",
        body_style
    ))
    
    story.append(Paragraph("What is dual control?", h3_style))
    story.append(Paragraph(
        "Dual control requires two different people to approve high-risk actions. This prevents "
        "single point of compromise, insider threats, and accidental approvals. The requester "
        "cannot approve their own request.",
        body_style
    ))
    
    # ============ TROUBLESHOOTING ============
    story.append(Paragraph("13. Troubleshooting", h1_style))
    
    story.append(Paragraph("Common Errors", h2_style))
    
    errors_data = [
        ['Error', 'Cause', 'Solution'],
        ['missing_poa', 'No PoA token provided', 'Get token from AgentAuth'],
        ['invalid_poa_signature', 'Token signature mismatch', 'Check signing key / AgentAuth'],
        ['token_expired', 'PoA exp claim in past', 'Request fresh token (5 min TTL)'],
        ['insufficient_approvals', 'High-risk needs more approvers', 'Collect additional approvals'],
        ['challenge_not_found', 'Challenge expired/invalid', 'Create new challenge'],
        ['x509: unknown authority', 'Certificate trust issue', 'Regenerate certs: make certs'],
    ]
    
    errors_table = Table(errors_data, colWidths=[1.8*inch, 1.8*inch, 2.4*inch])
    errors_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#742a2a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#fff5f5')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#feb2b2')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(errors_table)
    
    story.append(Paragraph("Development Issues", h2_style))
    
    story.append(Paragraph("Python Environment", h3_style))
    story.append(Paragraph("ModuleNotFoundError: Activate venv and reinstall dependencies:", body_style))
    py_fix = "source .venv/bin/activate<br/>pip install -r atb-gateway-py/requirements.txt"
    story.append(Paragraph(py_fix, code_style))
    
    story.append(Paragraph("Go Build Issues", h3_style))
    story.append(Paragraph("Cannot find main module: Run from correct directory:", body_style))
    go_fix = "cd atb-gateway-go<br/>go mod download<br/>go build ./cmd/broker"
    story.append(Paragraph(go_fix, code_style))
    
    story.append(Paragraph("Docker Issues", h3_style))
    story.append(Paragraph("Port already in use:", body_style))
    docker_fix = "lsof -i :8181  # Find process using port<br/>docker compose down<br/>docker compose up -d"
    story.append(Paragraph(docker_fix, code_style))
    
    story.append(Paragraph("OPA Policy Issues", h3_style))
    story.append(Paragraph("Check policy syntax and run tests:", body_style))
    opa_fix = "opa check opa/policy/<br/>opa test opa/policy/ -v --v0-compatible"
    story.append(Paragraph(opa_fix, code_style))
    
    # Build PDF
    doc.build(story)
    print("✅ PDF generated: ATB_Documentation.pdf")

if __name__ == "__main__":
    create_pdf()
