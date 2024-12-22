import requests

class Enrichment:
    @staticmethod
    def get_ip_location(ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            response.raise_for_status()
            data = response.json()
            
            if data['status'] == 'success':
                return {
                    'kraj': data.get('country'),
                    'miasto': data.get('city'),
                    'dostawca_usług_internetowych': data.get('isp')
                }
            else:
                return None
        except requests.RequestException as e:
            print(f"Wystąpił błąd podczas pobierania danych: {e}")
            return None
if __name__ == "__main__":
    ip = "8.8.8.8"  # Przykładowy adres IP
    enrichment = Enrichment()
    location = enrichment.get_ip_location(ip)

    if location:
        print("Dane o lokalizacji IP:")
        print(f"Kraj: {location['kraj']}")
        print(f"Miasto: {location['miasto']}")
        print(f"Dostawca usług internetowych: {location['dostawca_usług_internetowych']}")
    else:
        print("Nie udało się pobrać danych o lokalizacji IP.")
