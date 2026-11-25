"""Regression tripwires for the app's passive, warning-only network boundary.

This source check is not a formal sandbox for a rooted device. Changes to the
small privileged-command surface require review rather than silently adding an
automatic response path.
"""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def test_no_network_control_permissions_or_vpn_service():
    manifest = ET.parse(ROOT / 'android/app/src/main/AndroidManifest.xml').getroot()
    android = '{http://schemas.android.com/apk/res/android}'
    permissions = {node.attrib[android + 'name'] for node in manifest.findall('uses-permission')}
    assert not permissions.intersection({
        'android.permission.CHANGE_WIFI_STATE', 'android.permission.CHANGE_NETWORK_STATE',
        'android.permission.NETWORK_SETTINGS', 'android.permission.CONNECTIVITY_INTERNAL',
        'android.permission.BIND_VPN_SERVICE',
    })
    assert all(node.attrib.get(android + 'permission') != 'android.permission.BIND_VPN_SERVICE'
               for node in manifest.findall('./application/service'))


def test_privileged_command_surface_stays_capture_and_read_only():
    app = ROOT / 'android/app/src/main'
    expected = {'CaptureService.kt', 'ShortFlowCaptureService.kt', 'TsanetCaptureService.kt', 'UidResolver.kt'}
    builders = set()
    forbidden = re.compile(r'\b(?:iptables|ip6tables|nftables)\b|\b(?:setWifiEnabled|setMobileDataEnabled|bindProcessToNetwork)\s*\(')
    for source in app.rglob('*.kt'):
        text = source.read_text(encoding='utf-8')
        if 'ProcessBuilder(' in text or 'ProcessBuilder (' in text:
            builders.add(source.name)
            assert text.count('ProcessBuilder') == 1
            if source.name != 'UidResolver.kt':
                assert 'ProcessBuilder("su","-c","exec ' in text
                assert ' -w -"' in text
        # LocalExplainer contains the literal iptables only to reject it in
        # generated text. It must not gain a command execution API either.
        if source.name != 'LocalExplainer.kt':
            assert not forbidden.search(text), source
        assert not re.search(r'Runtime\.getRuntime\(\)\s*\.exec\s*\(', text), source
    assert builders == expected
    owners = (app / 'kotlin/nids/app/UidResolver.kt').read_text(encoding='utf-8')
    command = next(line.strip() for line in owners.splitlines() if 'val command=' in line)
    assert '/proc/net/tcp' in command and 'cat $it' in command and 'addr show' in command
    assert not re.search(r'\b(?:kill|set|add|del|flush|disable|enable|settings|svc)\b', command)
