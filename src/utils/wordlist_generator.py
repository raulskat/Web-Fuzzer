def generate_subdomains(size=20):
    """Generate a sample wordlist of common subdomains.
    
    Args:
        size (int): The number of subdomains to return.
        
    Returns:
        list: A list of common subdomain names.
    """
    common_subdomains = [
        'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
        'smtp', 'secure', 'vpn', 'api', 'dev', 'staging', 'test', 'admin',
        'ftp', 'cloud', 'portal', 'support', 'cpanel', 'web', 'host',
        'mx1', 'mx2', 'ns3', 'dns1', 'dns2', 'dns3', 'dns4', 'services',
        'cdn', 'static', 'assets', 'files', 'images', 'docs', 'beta',
        'alpha', 'demo', 'shop', 'store', 'mail2', 'smtp2', 'secure2',
        'chat', 'web2', 'portal2', 'admin2', 'server2', 'mobile', 'app'
    ]
    return common_subdomains[:min(size, len(common_subdomains))]

def generate_api_endpoints(size=15):
    """Generate a sample wordlist of common API endpoints.
    
    Args:
        size (int): The number of endpoints to return.
        
    Returns:
        list: A list of common API endpoint paths.
    """
    common_endpoints = [
        'api/v1', 'api/v2', 'api/v3', 'api/users', 'api/auth',
        'api/login', 'api/register', 'api/products', 'api/orders',
        'api/profile', 'api/settings', 'api/admin', 'api/config',
        'api/data', 'api/search', 'api/docs', 'api/stats',
        'api/metrics', 'api/health', 'api/status', 'api/info',
        'api/public', 'api/private', 'api/upload', 'api/download'
    ]
    return common_endpoints[:min(size, len(common_endpoints))]

