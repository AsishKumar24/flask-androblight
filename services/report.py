"""
PDF Report Generation Service
===============================
Generates downloadable PDF scan reports using ReportLab.
"""

from datetime import datetime

# Optional: PDF report generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import HexColor
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def generate_pdf_report(scan_result, output_path):
    """Generate PDF report of scan results. Returns output_path on success, None on failure."""
    if not REPORTLAB_AVAILABLE:
        return None
    
    try:
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        
        # Header
        c.setFillColor(HexColor('#1a1a2e'))
        c.rect(0, height - 80, width, 80, fill=1)
        
        c.setFillColor(HexColor('#00d9ff'))
        c.setFont("Helvetica-Bold", 24)
        c.drawString(50, height - 50, "AndroBlight Scan Report")
        
        c.setFillColor(HexColor('#ffffff'))
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        y = height - 120
        
        # File info
        c.setFillColor(HexColor('#000000'))
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "File Information")
        y -= 20
        
        c.setFont("Helvetica", 10)
        metadata = scan_result.get('metadata', {})
        c.drawString(60, y, f"File Name: {metadata.get('file_name', 'N/A')}")
        y -= 15
        c.drawString(60, y, f"Size: {metadata.get('file_size_readable', 'N/A')}")
        y -= 15
        c.drawString(60, y, f"SHA256: {metadata.get('sha256', 'N/A')[:32]}...")
        y -= 30
        
        # Detection result
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Detection Result")
        y -= 20
        
        ml = scan_result.get('ml_detection', {})
        label = ml.get('label', 'Unknown')
        confidence = ml.get('confidence', 0)
        
        if label == 'Malware':
            c.setFillColor(HexColor('#ff4444'))
        else:
            c.setFillColor(HexColor('#00cc00'))
        
        c.setFont("Helvetica-Bold", 16)
        c.drawString(60, y, f"{label} ({confidence:.1%})")
        y -= 30
        
        c.setFillColor(HexColor('#000000'))
        
        # Permission analysis
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Permission Analysis")
        y -= 20
        
        perm_analysis = scan_result.get('permission_analysis', {})
        c.setFont("Helvetica", 10)
        c.drawString(60, y, f"Total Permissions: {perm_analysis.get('total_count', 0)}")
        y -= 15
        c.drawString(60, y, f"Critical: {len(perm_analysis.get('critical', []))}")
        y -= 15
        c.drawString(60, y, f"High Risk: {len(perm_analysis.get('high', []))}")
        y -= 15
        c.drawString(60, y, f"Risk Score: {perm_analysis.get('risk_score', 0)}/100")
        
        c.save()
        return output_path
    except Exception as e:
        print(f"Error generating PDF: {e}")
        return None
