"""
Decimal Encoder — sérialisation JSON pour les grands entiers ZK
 
Ce module fournit un encodeur JSON personnalisé capable de gérer les types
Python non natifs : Decimal, datetime, bytes, et les grands entiers dépassant
la précision flottante JavaScript (> 2^53).
"""
import json
from decimal import Decimal
from datetime import datetime


class DecimalEncoder(json.JSONEncoder):
    """Encodeur JSON étendu pour la sérialisation des preuves ZK.
 
    Gère les types suivants qui ne sont pas supportés nativement par
    l'encodeur JSON standard :
    - ``Decimal`` → converti en float
    - ``datetime`` → converti en chaîne ISO 8601
    - ``bytes`` → converti en représentation hexadécimale
    - ``int`` dont la valeur absolue dépasse 2^53 → converti en chaîne
      afin de préserver la précision lors d'un échange avec JavaScript
    """

    def default(self, obj):
        """Convertit les types non-sérialisables en valeurs JSON compatibles.
 
        Surcharge la méthode ``default`` de ``json.JSONEncoder`` pour prendre
        en charge les types métier supplémentaires. Si le type de ``obj``
        n'est pas reconnu, la méthode parente est appelée et lève une
        ``TypeError``.
 
        Args:
            obj: L'objet Python à sérialiser.
 
        Returns:
            Une valeur JSON-sérialisable correspondant à ``obj`` :
            - ``float`` pour un ``Decimal``
            - ``str`` ISO 8601 pour un ``datetime``
            - ``str`` hexadécimale pour des ``bytes``
 
        Raises:
            TypeError: Si le type de ``obj`` n'est pas pris en charge.
        """

        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)

    def encode(self, obj):
        """Encode un objet Python en chaîne JSON.
 
        Appelle ``_conv`` en pré-traitement pour transformer les grands entiers
        en chaînes de caractères avant de déléguer l'encodage au moteur
        standard.
 
        Args:
            obj: L'objet Python racine à encoder (dict, list, scalaire…).
 
        Returns:
            str: La représentation JSON de ``obj``.
        """
        return super().encode(self._conv(obj))

    def _conv(self, obj):
        """Transforme récursivement les grands entiers en chaînes.
 
        Parcourt les structures imbriquées (dict, list) et convertit tout
        entier dont la valeur absolue dépasse 2^53 en ``str`` afin d'éviter
        toute perte de précision côté client JavaScript.
 
        Args:
            obj: L'objet à transformer (peut être un scalaire, un dict ou
                une list).
 
        Returns:
            L'objet transformé, de même structure que l'entrée, avec les
            grands entiers remplacés par leur représentation en chaîne.
        """

        if isinstance(obj, int) and abs(obj) > 2**53:
            return str(obj)
        if isinstance(obj, dict):
            return {k: self._conv(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._conv(i) for i in obj]
        return obj


def serialize_proof(data: dict) -> str:
    """Sérialise un dictionnaire de preuve ZK en JSON formaté.
 
    Utilise ``DecimalEncoder`` pour gérer tous les types non-standards
    présents dans les structures de preuves cryptographiques (grands entiers,
    octets, dates…).
 
    Args:
        data (dict): Le dictionnaire Python représentant la preuve à
            sérialiser.
 
    Returns:
        str: Une chaîne JSON indenté (2 espaces) représentant ``data``.
    """
    return json.dumps(data, cls=DecimalEncoder, indent=2)


def deserialize_proof(s: str) -> dict:
    """Désérialise une chaîne JSON en dictionnaire Python.
 
    Note:
        Les grands entiers précédemment convertis en chaînes lors de la
        sérialisation ne sont **pas** automatiquement reconvertis en ``int``
        à la désérialisation. Cette conversion doit être effectuée
        explicitement par l'appelant si nécessaire.
 
    Args:
        s (str): La chaîne JSON à désérialiser.
 
    Returns:
        dict: Le dictionnaire Python correspondant au JSON fourni.
 
    Raises:
        json.JSONDecodeError: Si ``s`` n'est pas un JSON valide.
    """
    return json.loads(s)