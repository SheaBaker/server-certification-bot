import sys
import json
import datetime


def check_certs(cert_data, warn_days):
    now = datetime.datetime.utcnow()
    alerts = []

    for cert in cert_data:
        name = cert.get('name', 'Unknown')
        endpoint = cert.get('endpoint', 'Unknown')
        not_after = cert.get('not_after', '')
        failed = cert.get('failed', False)

        if failed:
            alerts.append({
                'name': name,
                'endpoint': endpoint,
                'days_left': -1,
                'expires': 'N/A',
                'type': 'ERROR',
                'detail': 'Could not retrieve certificate'
            })
            continue

        try:
            not_after_clean = not_after.replace('Z', '')
            expiry = datetime.datetime.strptime(not_after_clean, '%Y%m%d%H%M%S')
            days_left = (expiry - now).days
            alert_type = 'WARN' if days_left <= warn_days else 'OK'
        except Exception as e:
            alerts.append({
                'name': name,
                'endpoint': endpoint,
                'days_left': -1,
                'expires': not_after,
                'type': 'ERROR',
                'detail': 'Could not parse expiry date: ' + str(e)
            })
            continue

        alerts.append({
            'name': name,
            'endpoint': endpoint,
            'days_left': days_left,
            'expires': expiry.strftime('%Y-%m-%d'),
            'type': alert_type,
            'detail': ''
        })

    return alerts


def build_message(alerts, warn_days):
    bad = [a for a in alerts if a['type'] in ('WARN', 'ERROR')]
    NL = chr(10)

    if not bad:
        return '**CERT ALERTS** (threshold ' + str(warn_days) + ' days)' + NL + NL + 'All certificates are valid and not expiring soon.'

    lines = ['**CERT ALERTS** (threshold ' + str(warn_days) + ' days)' + NL]
    for a in bad:
        status = 'ERROR' if a['type'] == 'ERROR' else 'EXPIRING'
        lines.append('- **' + a['name'] + '**')
        lines.append("  - Endpoint: '" + a['endpoint'] + "'")
        lines.append('  - Status: ' + status)
        if a['type'] == 'ERROR':
            lines.append('  - Detail: ' + a['detail'])
        else:
            lines.append('  - Days left: **' + str(a['days_left']) + '**')
            lines.append('  - Expires: ' + a['expires'])

    return NL.join(lines)


if __name__ == '__main__':
    with open(sys.argv[1], 'r') as f:
        cert_data = json.load(f)
    warn_days = int(sys.argv[2])

    alerts = check_certs(cert_data, warn_days)
    message = build_message(alerts, warn_days)

    output = {
        'alerts': alerts,
        'message': message,
        'has_alerts': any(a['type'] in ('WARN', 'ERROR') for a in alerts)
    }

    print(json.dumps(output))