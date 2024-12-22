import requests

class Enrichment:
    @staticmethod
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
                Enrichment.print_ip_location(location_data)
                return location_data
            else:
                print("Nie udało się pobrać danych o lokalizacji IP.")
                return None
        except requests.RequestException as e:
            print(f"Wystąpił błąd podczas pobierania danych: {e}")
            return None

    @staticmethod
    def print_ip_location(location_data):
        print("     Dane o lokalizacji IP:")
        print(f"        Kraj: {location_data['kraj']}")
        print(f"        Miasto: {location_data['miasto']}")
        print(f"        Dostawca usług internetowych: {location_data['dostawca_usług_internetowych']}")

if __name__ == "__main__":
    ip = "8.8.8.8"  # Przykładowy adres IP
    enrichment = Enrichment()
    enrichment.get_ip_location(ip)
