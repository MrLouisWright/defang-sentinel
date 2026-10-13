export const RULES = {
  'live-link': { severity: 'high', title: 'Clickable link to a live IOC (Markdown/HTML href or autolink)', group: 'link' },
  'live-url': { severity: 'high', title: 'URL is not defanged', group: 'url' },
  'partial-defang': { severity: 'medium', title: 'Indicator is only partly defanged (e.g. hxxp:// with a live host)', group: 'url' },
  'live-domain': { severity: 'medium', title: 'Domain is not defanged', group: 'domain' },
  'live-ip': { severity: 'medium', title: 'Public IP address is not defanged', group: 'ip' },
  'live-email': { severity: 'low', title: 'Email address is not defanged', group: 'email' },
};
