"""
Metrics Collector — métriques de performance ZK
Singleton global, données en mémoire + base de données.
 
Ce module expose un collecteur de métriques singleton (``_collector``) destiné
à enregistrer et résumer les performances des preuves ZK générées et vérifiées
au sein du système. Les données sont conservées en mémoire durant la durée de
vie du processus.
"""
from datetime import datetime
from typing import Dict, Any, List
from dataclasses import dataclass, field


@dataclass
class ProofMetric:
    """Représente les métriques associées à une preuve ZK unique.
 
    Chaque instance capture un instantané de performance au moment de la
    génération/vérification d'une preuve : temps de traitement, taille,
    validité et parties impliquées.
 
    Attributes:
        proof_uid (str): Identifiant unique de la preuve.
        hospital_name (str): Nom de l'hôpital émetteur de la preuve.
        insurer_name (str): Nom de l'assureur destinataire de la preuve.
        generation_time_ms (float): Durée de génération de la preuve en
            millisecondes.
        verification_time_ms (float): Durée de vérification de la preuve en
            millisecondes.
        proof_size_bytes (int): Taille de la preuve sérialisée en octets.
        is_valid (bool): ``True`` si la preuve a passé la vérification,
            ``False`` sinon.
        timestamp (str): Horodatage UTC de l'enregistrement au format ISO 8601,
            généré automatiquement à la création de l'instance.
    """

    proof_uid: str
    hospital_name: str
    insurer_name: str
    generation_time_ms: float
    verification_time_ms: float
    proof_size_bytes: int
    is_valid: bool
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class MetricsCollector:
    """Collecteur de métriques de performance pour les preuves ZK.
 
    Stocke en mémoire la liste de toutes les métriques enregistrées depuis
    le démarrage du processus et fournit un résumé statistique agrégé.
 
    Cette classe est instanciée une seule fois en tant que singleton global
    ``_collector`` ; utiliser ``get_collector()`` pour y accéder.
 
    Attributes:
        _data (List[ProofMetric]): Liste interne des métriques enregistrées,
            par ordre chronologique d'insertion.
    """
    def __init__(self):
        """Initialise le collecteur avec une liste de métriques vide."""
        self._data: List[ProofMetric] = []

    def record(self, proof_uid: str, hospital_name: str, insurer_name: str,
               generation_time_ms: float, verification_time_ms: float,
               proof_size_bytes: int, is_valid: bool):
         
        """Enregistre les métriques d'une preuve ZK.
 
        Crée une instance de ``ProofMetric`` horodatée automatiquement et
        l'ajoute à la liste interne.
 
        Args:
            proof_uid (str): Identifiant unique de la preuve.
            hospital_name (str): Nom de l'hôpital émetteur.
            insurer_name (str): Nom de l'assureur destinataire.
            generation_time_ms (float): Temps de génération en millisecondes.
            verification_time_ms (float): Temps de vérification en
                millisecondes.
            proof_size_bytes (int): Taille de la preuve en octets.
            is_valid (bool): Résultat de la vérification de la preuve.
        """
        self._data.append(ProofMetric(
            proof_uid=proof_uid,
            hospital_name=hospital_name,
            insurer_name=insurer_name,
            generation_time_ms=generation_time_ms,
            verification_time_ms=verification_time_ms,
            proof_size_bytes=proof_size_bytes,
            is_valid=is_valid,
        ))

    def get_summary(self) -> Dict[str, Any]:
        """Calcule et retourne un résumé statistique des métriques collectées.
 
        Agrège l'ensemble des enregistrements en mémoire pour produire des
        indicateurs clés de performance. Les 50 enregistrements les plus
        récents sont inclus dans le champ ``records``, triés du plus récent
        au plus ancien.
 
        Returns:
            Dict[str, Any]: Un dictionnaire contenant les clés suivantes :
 
            - ``total`` (int): Nombre total de preuves enregistrées.
            - ``success_rate`` (float): Pourcentage de preuves valides,
              arrondi à une décimale.
            - ``avg_gen_ms`` (float): Temps moyen de génération en ms,
              arrondi à deux décimales.
            - ``avg_ver_ms`` (float): Temps moyen de vérification en ms,
              arrondi à deux décimales.
            - ``avg_size_kb`` (float): Taille moyenne des preuves en Ko,
              arrondie à deux décimales.
            - ``records`` (list[dict]): Liste des 50 derniers enregistrements,
              chacun exposant les champs ``proof_uid``, ``hospital``,
              ``insurer``, ``gen_ms``, ``ver_ms``, ``size_bytes``, ``valid``
              et ``ts``.
 
            Si aucune métrique n'a été enregistrée, toutes les valeurs
            numériques sont à ``0`` et ``records`` est une liste vide.
        """

        if not self._data:
            return {
                "total": 0, "success_rate": 0,
                "avg_gen_ms": 0, "avg_ver_ms": 0,
                "avg_size_kb": 0, "records": []
            }
        n = len(self._data)
        ok = sum(1 for m in self._data if m.is_valid)
        avg_gen = sum(m.generation_time_ms for m in self._data) / n
        avg_ver = sum(m.verification_time_ms for m in self._data) / n
        avg_sz  = sum(m.proof_size_bytes for m in self._data) / n
        
        return {
            "total": n,
            "success_rate": round(ok / n * 100, 1),
            "avg_gen_ms": round(avg_gen, 3),
            "avg_ver_ms": round(avg_ver, 3),
            "avg_size_kb": round(avg_sz / 1024, 3),
            "records": [
                {
                    "proof_uid": m.proof_uid,
                    "hospital": m.hospital_name,
                    "insurer": m.insurer_name,
                    "gen_ms": m.generation_time_ms,
                    "ver_ms": m.verification_time_ms,
                    "size_bytes": m.proof_size_bytes,
                    "valid": m.is_valid,
                    "ts": m.timestamp,
                }
                for m in reversed(self._data[-50:])
            ]
        }

    def clear(self):
        """Efface toutes les métriques conservées en mémoire.
 
        Remet la liste interne ``_data`` à zéro. Les données supprimées ne
        sont pas récupérables ; cette méthode est principalement destinée aux
        tests ou à la réinitialisation du collecteur en cours d'exécution.
        """
        self._data.clear()


_collector = MetricsCollector()


def get_collector() -> MetricsCollector:
    """Retourne l'instance singleton du collecteur de métriques.
 
    Fournit un point d'accès global unique à ``_collector``, garantissant
    que toutes les parties du système partagent le même état de métriques
    sans avoir à instancier ``MetricsCollector`` elles-mêmes.
 
    Returns:
        MetricsCollector: L'instance singleton du collecteur de métriques.
    """
    return _collector