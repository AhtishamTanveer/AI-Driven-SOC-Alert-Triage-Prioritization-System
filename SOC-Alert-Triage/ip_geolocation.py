import random

class IPGeolocation:
    """Mock geolocation for IP addresses (for demo purposes)"""
    
    def __init__(self):
        # Common attack source countries with realistic coordinates
        self.attack_sources = {
            'China': {'lat': 35.8617, 'lon': 104.1954, 'code': 'CN'},
            'Russia': {'lat': 61.5240, 'lon': 105.3188, 'code': 'RU'},
            'North Korea': {'lat': 40.3399, 'lon': 127.5101, 'code': 'KP'},
            'Iran': {'lat': 32.4279, 'lon': 53.6880, 'code': 'IR'},
            'Brazil': {'lat': -14.2350, 'lon': -51.9253, 'code': 'BR'},
            'Nigeria': {'lat': 9.0820, 'lon': 8.6753, 'code': 'NG'},
            'India': {'lat': 20.5937, 'lon': 78.9629, 'code': 'IN'},
            'Vietnam': {'lat': 14.0583, 'lon': 108.2772, 'code': 'VN'},
            'Romania': {'lat': 45.9432, 'lon': 24.9668, 'code': 'RO'},
            'Ukraine': {'lat': 48.3794, 'lon': 31.1656, 'code': 'UA'},
            'Pakistan': {'lat': 30.3753, 'lon': 69.3451, 'code': 'PK'},
            'USA': {'lat': 37.0902, 'lon': -95.7129, 'code': 'US'},
            'Germany': {'lat': 51.1657, 'lon': 10.4515, 'code': 'DE'},
            'Turkey': {'lat': 38.9637, 'lon': 35.2433, 'code': 'TR'},
            'Indonesia': {'lat': -0.7893, 'lon': 113.9213, 'code': 'ID'},
            'Bangladesh': {'lat': 23.6850, 'lon': 90.3563, 'code': 'BD'},
            'Mexico': {'lat': 23.6345, 'lon': -102.5528, 'code': 'MX'},
            'France': {'lat': 46.2276, 'lon': 2.2137, 'code': 'FR'},
            'UK': {'lat': 55.3781, 'lon': -3.4360, 'code': 'GB'},
            'South Korea': {'lat': 35.9078, 'lon': 127.7669, 'code': 'KR'},
        }
        
        # Malicious IP patterns (simplified for demo)
        self.known_malicious_ips = [
            '185.220.101.1',   # Tor exit node
            '198.51.100.78',   # Known scanner
            '203.0.113.45',    # Malicious IP
        ]
    
    def get_location(self, ip_address):
        """Get location for an IP address"""
        
        # Check if it's a known malicious IP
        if ip_address in self.known_malicious_ips:
            # Randomly assign a known attack source country
            country = random.choice(['China', 'Russia', 'North Korea', 'Iran'])
            location = self.attack_sources[country].copy()
            location['country'] = country
            location['is_malicious'] = True
            # Add some randomness to coordinates for clustering
            location['lat'] += random.uniform(-5, 5)
            location['lon'] += random.uniform(-5, 5)
            return location
        
        # For localhost/private IPs, show as Pakistan (your location)
        if ip_address in ['127.0.0.1', 'N/A', 'localhost'] or ip_address.startswith('192.168') or ip_address.startswith('10.'):
            return {
                'country': 'Pakistan',
                'lat': 33.6844 + random.uniform(-0.5, 0.5),  # Islamabad
                'lon': 73.0479 + random.uniform(-0.5, 0.5),
                'code': 'PK',
                'is_malicious': False
            }
        
        # For other IPs, randomly assign attack source countries
        # Exclude Pakistan from attack sources
        attack_countries = [c for c in self.attack_sources.keys() if c != 'Pakistan']
        country = random.choice(attack_countries)
        location = self.attack_sources[country].copy()
        location['country'] = country
        location['is_malicious'] = random.random() > 0.5
        # Add variation for multiple attacks from same country
        location['lat'] += random.uniform(-3, 3)
        location['lon'] += random.uniform(-3, 3)
        return location
    
    def get_attack_statistics(self, alerts_df):
        """Generate attack statistics by country"""
        country_stats = {}
        
        for _, alert in alerts_df.iterrows():
            location = self.get_location(alert['source_ip'])
            country = location['country']
            
            if country not in country_stats:
                country_stats[country] = {
                    'count': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'lat': location['lat'],
                    'lon': location['lon'],
                    'code': location['code']
                }
            
            country_stats[country]['count'] += 1
            priority = alert['priority'].lower()
            if priority in country_stats[country]:
                country_stats[country][priority] += 1
        
        return country_stats