import requests

def get_ip_location(ip):
    try:
        ip = "8.8.8.8"
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response.raise_for_status()
        data = response.json()

        if data['status'] == 'success':
            location_data = {
                'kraj': data.get('country'),
                'miasto': data.get('city'),
                'dostawca_usług_internetowych': data.get('isp')
            }
            return location_data
        else:
            print("Nie udało się pobrać danych o lokalizacji IP.")
            return None
    except requests.RequestException as e:
        print(f"Wystąpił błąd podczas pobierania danych: {e}")
        return None
