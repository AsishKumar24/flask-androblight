"""
Permissions Database
====================
All dangerous permissions, suspicious combinations, and malware family
classification data used during APK analysis.
"""

# Known dangerous Android permissions with risk levels
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS': {
        'level': 'critical',
        'description': 'Read SMS messages',
        'risk': 'Can access private messages and OTPs'
    },
    'android.permission.SEND_SMS': {
        'level': 'critical', 
        'description': 'Send SMS messages',
        'risk': 'Can send premium SMS causing charges'
    },
    'android.permission.READ_CONTACTS': {
        'level': 'high',
        'description': 'Read contacts',
        'risk': 'Can harvest contact information'
    },
    'android.permission.READ_CALL_LOG': {
        'level': 'high',
        'description': 'Read call history',
        'risk': 'Can monitor communication patterns'
    },
    'android.permission.RECORD_AUDIO': {
        'level': 'critical',
        'description': 'Record audio',
        'risk': 'Can secretly record conversations'
    },
    'android.permission.CAMERA': {
        'level': 'high',
        'description': 'Access camera',
        'risk': 'Can take photos/videos without consent'
    },
    'android.permission.ACCESS_FINE_LOCATION': {
        'level': 'high',
        'description': 'Precise location access',
        'risk': 'Can track user location precisely'
    },
    'android.permission.ACCESS_COARSE_LOCATION': {
        'level': 'medium',
        'description': 'Approximate location',
        'risk': 'Can track user location approximately'
    },
    'android.permission.READ_EXTERNAL_STORAGE': {
        'level': 'medium',
        'description': 'Read storage',
        'risk': 'Can access files on device'
    },
    'android.permission.WRITE_EXTERNAL_STORAGE': {
        'level': 'medium',
        'description': 'Write storage',
        'risk': 'Can modify files on device'
    },
    'android.permission.INTERNET': {
        'level': 'low',
        'description': 'Internet access',
        'risk': 'Can send data to remote servers'
    },
    'android.permission.RECEIVE_BOOT_COMPLETED': {
        'level': 'medium',
        'description': 'Run at startup',
        'risk': 'Can run automatically when device boots'
    },
    'android.permission.SYSTEM_ALERT_WINDOW': {
        'level': 'critical',
        'description': 'Draw over other apps',
        'risk': 'Can display fake overlays for phishing'
    },
    'android.permission.REQUEST_INSTALL_PACKAGES': {
        'level': 'critical',
        'description': 'Install apps',
        'risk': 'Can install additional malware'
    },
    'android.permission.BIND_ACCESSIBILITY_SERVICE': {
        'level': 'critical',
        'description': 'Accessibility service',
        'risk': 'Can monitor and control device actions'
    },
    'android.permission.BIND_DEVICE_ADMIN': {
        'level': 'critical',
        'description': 'Device administrator',
        'risk': 'Can lock device, wipe data, change settings'
    },
    'android.permission.READ_PHONE_STATE': {
        'level': 'medium',
        'description': 'Read phone state',
        'risk': 'Can access device identifiers'
    },
    'android.permission.PROCESS_OUTGOING_CALLS': {
        'level': 'high',
        'description': 'Monitor outgoing calls',
        'risk': 'Can intercept or redirect calls'
    },
    'android.permission.RECEIVE_SMS': {
        'level': 'critical',
        'description': 'Receive SMS',
        'risk': 'Can intercept incoming messages'
    },
}

# Suspicious permission combinations that indicate specific threats
SUSPICIOUS_COMBOS = [
    {
        'permissions': ['android.permission.INTERNET', 'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS'],
        'threat': 'SMS Stealer',
        'description': 'Can intercept and send SMS messages to remote server'
    },
    {
        'permissions': ['android.permission.INTERNET', 'android.permission.RECORD_AUDIO', 'android.permission.CAMERA'],
        'threat': 'Spyware',
        'description': 'Can record audio/video and send to remote server'
    },
    {
        'permissions': ['android.permission.INTERNET', 'android.permission.ACCESS_FINE_LOCATION', 'android.permission.READ_CONTACTS'],
        'threat': 'Stalkerware',
        'description': 'Can track location and harvest contacts'
    },
    {
        'permissions': ['android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.INTERNET'],
        'threat': 'Banking Trojan',
        'description': 'Can display fake overlays to steal credentials'
    },
    {
        'permissions': ['android.permission.BIND_DEVICE_ADMIN', 'android.permission.INTERNET'],
        'threat': 'Ransomware',
        'description': 'Can lock device and demand ransom'
    },
    {
        'permissions': ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INTERNET'],
        'threat': 'Dropper',
        'description': 'Can download and install additional malware'
    },
]

# Malware family classification based on CNN output confidence ranges
MALWARE_FAMILIES = {
    'adware': {'min_conf': 0.5, 'max_conf': 0.65, 'description': 'Displays unwanted advertisements'},
    'trojan': {'min_conf': 0.65, 'max_conf': 0.8, 'description': 'Disguised malicious software'},
    'spyware': {'min_conf': 0.8, 'max_conf': 0.9, 'description': 'Monitors user activity secretly'},
    'ransomware': {'min_conf': 0.9, 'max_conf': 1.0, 'description': 'Encrypts files and demands payment'},
}
