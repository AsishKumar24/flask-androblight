"""
Certificate Analysis Service
==============================
Extracts and analyzes APK signing certificate information.
"""

import os
import hashlib


def extract_certificate_info(extract_dir):
    """Extract certificate information from APK's META-INF directory"""
    cert_info = {
        'signed': False,
        'issuer': None,
        'subject': None,
        'valid_from': None,
        'valid_to': None,
        'fingerprint_sha256': None,
        'debug_signed': False
    }
    
    # Look for certificate files
    meta_inf = os.path.join(extract_dir, 'META-INF')
    if not os.path.exists(meta_inf):
        return cert_info
    
    for filename in os.listdir(meta_inf):
        if filename.endswith('.RSA') or filename.endswith('.DSA'):
            cert_path = os.path.join(meta_inf, filename)
            cert_info['signed'] = True
            
            # Calculate fingerprint
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
                cert_info['fingerprint_sha256'] = hashlib.sha256(cert_data).hexdigest()
            
            # Check for debug signature
            strings = _extract_strings_from_binary(cert_data)
            for s in strings:
                if 'debug' in s.lower() or 'android debug' in s.lower():
                    cert_info['debug_signed'] = True
                if 'CN=' in s:
                    cert_info['subject'] = s
            
            break
    
    return cert_info


def _extract_strings_from_binary(content):
    """Extract readable strings from binary content"""
    strings = []
    current = []
    
    for byte in content:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= 5:
                strings.append(''.join(current))
            current = []
    
    if len(current) >= 5:
        strings.append(''.join(current))
    
    return strings
