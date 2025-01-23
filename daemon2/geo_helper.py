# geo_helper.py

import logging
from geoip2.database import Reader

# Configuração do logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def get_geo_info(ip_address):
    """
    Busca informações de geolocalização de um endereço IP usando a base MaxMind.
    
    :param ip_address: Endereço IP a ser consultado.
    :return: Dicionário contendo as informações de geolocalização (país, cidade, latitude, longitude).
    """
    try:
        with Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            return {
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
    except Exception as e:
        logger.error(f"Erro ao obter informações de geolocalização para {ip_address}: {e}")
        return {"country_code": None, "city": None, "latitude": None, "longitude": None}
