"""
Bulletproofs-inspired Range Proof
==================================
Schéma : Pedersen Commitment + Range Proof binaire + Protocole Sigma (Fiat-Shamir)
Prédicat unique : température < 38°C (précision décimale arbitraire)

Correction fondamentale :
  r_w = Σ r_i * 2^i  mod q   (lié aux blindings des bits)
  C_w est recalculé depuis r_w pour garantir la cohérence binaire.

Architecture :
  - PedersenCommitment : engagement homomorphique masquant la valeur
  - SigmaProtocol      : preuve de connaissance non-interactive (Fiat-Shamir)
  - RangeProofEngine   : preuve de borne par décomposition binaire
  - BulletproofsHandler: interface haut niveau pour le prédicat T < 38°C
"""

import hashlib
import secrets
import time
from typing import Tuple, Dict, Any, Optional
from decimal import Decimal, getcontext

getcontext().prec = 50

_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D6"
    "70C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE3"
    "9E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2"
    "BCBF6955817183995497CEA956AE515D2261898FA051015728"
    "E5A8AACAA68FFFFFFFFFFFFFFFF"
)

"""
Nombre premier sûr de 2048 bits (RFC 3526 MODP Group 14).
Utilisé comme module pour toutes les opérations d'exponentiation modulaire.
p = 2q + 1 où q est aussi premier (safe prime).
"""
PRIME_P = int(_PRIME_HEX, 16)

"""
Ordre du sous-groupe utilisé pour les scalaires (blindings, réponses Sigma).
q = (p - 1) / 2, également premier.
"""
PRIME_Q = (PRIME_P - 1) // 2


def _compute_scale(value: float) -> int:
    """
    Calcule le facteur d'échelle nécessaire pour convertir un flottant en entier
    sans perte de précision décimale.

    Exemple :
        _compute_scale(37.25)  → 100
        _compute_scale(38.0)   → 1
        _compute_scale(37.1253)→ 10000

    Args:
        value: La valeur flottante à analyser.

    Returns:
        Un entier 10^d où d est le nombre de décimales de value.
    """

    s = str(Decimal(str(value)))
    if '.' in s:
        decimals = len(s.split('.')[1])
    else:
        decimals = 0
    return 10 ** decimals


class PedersenCommitment:
    """
    Schéma d'engagement de Pedersen sur un groupe multiplicatif mod p.

    Un engagement de Pedersen C = g^v * h^r mod p permet de :
      - Cacher la valeur v (propriété de masquage : hiding)
      - Lier l'engagement à v de façon infalsifiable (propriété de liaison : binding)
      - Combiner des engagements de façon homomorphique :
          C(v1) * C(v2) = C(v1 + v2)

    Paramètres publics : p, g, h
    Valeur secrète    : v (la température)
    Facteur aveuglant : r (nombre aléatoire, gardé secret)
    """

    def __init__(self, p: int = PRIME_P, g: int = 2, h: Optional[int] = None):
        """
        Initialise le schéma de Pedersen avec les paramètres du groupe.

        Args:
            p: Nombre premier sûr (module). Par défaut : RFC 3526 Group 5.
            g: Générateur du groupe. Par défaut : 2.
            h: Second générateur indépendant de g.
               Si None, dérivé de façon déterministe via SHA-256.
               La relation log_g(h) doit être inconnue pour garantir le binding.
        """

        self.p = p
        self.q = (p - 1) // 2
        self.g = g
        if h is None:
            seed = hashlib.sha256(b"ZK_MEDICAL_H_GENERATOR_v2").digest()
            h_raw = int.from_bytes(seed, 'big') % (p - 2) + 2
            self.h = pow(h_raw, 2, p)
        else:
            self.h = h

    def commit(self, value: int, blinding: Optional[int] = None) -> Tuple[int, int]:
        """
        Crée un engagement de Pedersen pour une valeur entière.

        Calcul : C = g^value * h^blinding mod p

        Args:
            value:    La valeur entière à engager (ex: 372 pour 37.2°C × 10).
            blinding: Facteur aveuglant r ∈ [0, q). Généré aléatoirement si None.

        Returns:
            Tuple (C, blinding) où C est l'engagement public et blinding le secret.
        """

        if blinding is None:
            blinding = secrets.randbelow(self.q)
        C = (pow(self.g, value, self.p) * pow(self.h, blinding, self.p)) % self.p
        return C, blinding

    def verify_open(self, C: int, value: int, blinding: int) -> bool:
        """
        Vérifie qu'un engagement s'ouvre correctement sur (value, blinding).

        Recalcule g^value * h^blinding mod p et compare à C.
        Utilisé uniquement par le prouveur pour ses propres vérifications internes.

        Args:
            C:        L'engagement à vérifier.
            value:    La valeur supposée.
            blinding: Le facteur aveuglant supposé.

        Returns:
            True si C == g^value * h^blinding mod p, False sinon.
        """
        expected = (pow(self.g, value, self.p) * pow(self.h, blinding, self.p)) % self.p
        return C == expected


class SigmaProtocol:
    """
    Protocole Sigma de Schnorr rendu non-interactif via l'heuristique de Fiat-Shamir.

    Prouve la connaissance d'une valeur v et d'un blinding r tels que
    C = g^v * h^r mod p, sans révéler v ni r.

    Déroulement (non-interactif) :
      1. Prouveur choisit k1, k2 aléatoires → R = g^k1 * h^k2
      2. Défi c = H(C, R, label, p, g, h)  [Fiat-Shamir]
      3. Réponses : s1 = k1 - c*v mod q,  s2 = k2 - c*r mod q
      4. Vérifieur contrôle : g^s1 * h^s2 * C^c == R
    """

    def __init__(self, pedersen: PedersenCommitment):
        """
        Initialise le protocole Sigma avec les paramètres d'un engagement de Pedersen.

        Args:
            pedersen: Instance PedersenCommitment fournissant p, q, g, h.
        """

        self.p = pedersen.p
        self.q = pedersen.q
        self.g = pedersen.g
        self.h = pedersen.h

    def _challenge(self, *elements) -> int:
        """
        Calcule le défi de Fiat-Shamir : c = H(elements...) mod q.

        Hache tous les éléments passés en argument via SHA-256.
        Les entiers sont convertis en bytes big-endian.
        Les chaînes sont encodées en UTF-8.

        Args:
            *elements: Éléments à inclure dans le hachage (int, str, bytes).

        Returns:
            Un entier c ∈ [0, q).
        """

        hsh = hashlib.sha256()
        for e in elements:
            if isinstance(e, int):
                hsh.update(e.to_bytes((e.bit_length() + 7) // 8 or 1, 'big'))
            elif isinstance(e, (str, bytes)):
                hsh.update(e.encode() if isinstance(e, str) else e)
        return int(hsh.hexdigest(), 16) % self.q

    def prove(self, value: int, C: int, r: int, label: str) -> Dict[str, Any]:
        """
        Génère une preuve de connaissance non-interactive pour (value, r) dans C.

        Étapes :
          1. Tire k1, k2 aléatoires dans [0, q)
          2. Calcule R = g^k1 * h^k2 mod p
          3. Calcule le défi c = H(C, R, label, p, g, h) mod q
          4. Calcule s1 = k1 - c*value mod q
          5. Calcule s2 = k2 - c*r mod q

        Args:
            value: La valeur secrète engagée (entier).
            C:     L'engagement de Pedersen correspondant.
            r:     Le facteur aveuglant utilisé pour C.
            label: Étiquette contextuelle pour le défi (prévient la réutilisation).

        Returns:
            Dictionnaire contenant {C, R, c, s1, s2, label}.
        """

        k1 = secrets.randbelow(self.q)
        k2 = secrets.randbelow(self.q)
        R  = (pow(self.g, k1, self.p) * pow(self.h, k2, self.p)) % self.p
        c  = self._challenge(C, R, label, self.p, self.g, self.h)
        s1 = (k1 - c * value) % self.q
        s2 = (k2 - c * r)     % self.q
        return {"C": C, "R": R, "c": c, "s1": s1, "s2": s2, "label": label}

    def verify(self, proof: Dict[str, Any]) -> bool:
        """
        Vérifie une preuve de connaissance Sigma.

        Contrôles effectués :
          1. Recalcule c' = H(C, R, label, p, g, h) et vérifie c == c'
          2. Vérifie l'équation : g^s1 * h^s2 * C^c == R mod p

        Args:
            proof: Dictionnaire produit par prove() contenant {C, R, c, s1, s2, label}.

        Returns:
            True si la preuve est valide, False sinon.
        """

        try:
            C     = int(proof["C"])
            R     = int(proof["R"])
            c     = int(proof["c"])
            s1    = int(proof["s1"])
            s2    = int(proof["s2"])
            label = proof["label"]
            c_check = self._challenge(C, R, label, self.p, self.g, self.h)
            if c != c_check:
                return False
            lhs = (pow(self.g, s1, self.p) * pow(self.h, s2, self.p) * pow(C, c, self.p)) % self.p
            return lhs == R
        except Exception:
            return False


class RangeProofEngine:
    """
    Moteur de preuve de borne par décomposition binaire.

    Stratégie :
      1. Convertir v en entier w = v_int - lo_int (décalage par rapport au minimum)
      2. Décomposer w en n bits : w = Σ b_i * 2^i
      3. Pour chaque bit b_i, créer un engagement C_i = g^b_i * h^r_i
      4. Prouver que chaque C_i engage un bit (0 ou 1) via preuve OR disjonctive
      5. Prouver la cohérence : C_w = Π C_i^{2^i} mod p
      6. Prouver la connaissance de (w, r_w) dans C_w via protocole Sigma

    Propriété clé : r_w = Σ r_i * 2^i mod q garantit la cohérence homomorphique.
    """

    def __init__(self, pedersen: PedersenCommitment, sigma: SigmaProtocol):
        """
        Initialise le moteur de preuve de borne.

        Args:
            pedersen: Schéma d'engagement de Pedersen.
            sigma:    Protocole Sigma pour les preuves de connaissance.
        """

        self.ped   = pedersen
        self.sigma = sigma
        self.p = pedersen.p
        self.q = pedersen.q
        self.g = pedersen.g
        self.h = pedersen.h

    def _prove_bit(self, bit: int, C: int, r: int, label: str) -> Dict[str, Any]:
        """
        Génère une preuve OR disjonctive que C engage un bit (0 ou 1).

        Principe (preuve OR de Cramer-Damgård-Schoenmakers) :
          - Pour le bit réel, génère une vraie preuve Schnorr.
          - Pour l'autre bit, simule une preuve valide (possible sans connaître le secret).
          - Le défi global c_tot = c0 + c1 est lié aux deux branches via Fiat-Shamir.
          - Le vérifieur ne peut pas distinguer quelle branche est réelle.

        Équation de vérification pour chaque branche :
          Branche 0 : g^s0_1 * h^s0_2 * C^c0  == R0   (C  engage 0)
          Branche 1 : g^s1_1 * h^s1_2 * C1^c1 == R1   (C1 = C/g engage 0, donc C engage 1)

        Args:
            bit:   Le bit réel (0 ou 1).
            C:     L'engagement g^bit * h^r mod p.
            r:     Le blinding utilisé pour C.
            label: Étiquette contextuelle pour le défi.

        Returns:
            Dictionnaire contenant toutes les composantes de la preuve OR.
        """

        assert bit in (0, 1)
        g_inv = pow(self.g, self.p - 2, self.p)
        C1    = (C * g_inv) % self.p  

        if bit == 0:
            # Branche réelle : connaissance de (0, r) dans C = h^r
            k1 = secrets.randbelow(self.q)
            k2 = secrets.randbelow(self.q)
            R0 = (pow(self.g, k1, self.p) * pow(self.h, k2, self.p)) % self.p

            # Simulation branche b=1 (sur C1)
            c1_sim   = secrets.randbelow(self.q)
            s1_1_sim = secrets.randbelow(self.q)
            s1_2_sim = secrets.randbelow(self.q)
            R1_sim = (
                pow(self.g, s1_1_sim, self.p) *
                pow(self.h, s1_2_sim, self.p) *
                pow(C1, c1_sim, self.p)
            ) % self.p

            c_tot = self.sigma._challenge(C, R0, R1_sim, label)
            c0    = (c_tot - c1_sim) % self.q
            s0_1  = (k1 - c0 * 0) % self.q  # valeur=0 → k1
            s0_2  = (k2 - c0 * r) % self.q

            return {
                "C": C, "R0": R0, "R1": R1_sim,
                "c0": c0, "c1": c1_sim,
                "s0_1": s0_1, "s0_2": s0_2,
                "s1_1": s1_1_sim, "s1_2": s1_2_sim,
                "label": label,
            }
        else:
            # Branche réelle : connaissance de (0, r) dans C1 = h^r
            k1 = secrets.randbelow(self.q)
            k2 = secrets.randbelow(self.q)
            R1 = (pow(self.g, k1, self.p) * pow(self.h, k2, self.p)) % self.p

            # Simulation branche b=0 (sur C)
            c0_sim   = secrets.randbelow(self.q)
            s0_1_sim = secrets.randbelow(self.q)
            s0_2_sim = secrets.randbelow(self.q)
            R0_sim = (
                pow(self.g, s0_1_sim, self.p) *
                pow(self.h, s0_2_sim, self.p) *
                pow(C, c0_sim, self.p)
            ) % self.p

            c_tot = self.sigma._challenge(C, R0_sim, R1, label)
            c1    = (c_tot - c0_sim) % self.q
            s1_1  = (k1 - c1 * 0) % self.q  # valeur=0 dans C1 → k1
            s1_2  = (k2 - c1 * r) % self.q

            return {
                "C": C, "R0": R0_sim, "R1": R1,
                "c0": c0_sim, "c1": c1,
                "s0_1": s0_1_sim, "s0_2": s0_2_sim,
                "s1_1": s1_1, "s1_2": s1_2,
                "label": label,
            }

    def _verify_bit(self, proof: Dict[str, Any]) -> bool:
        """
        Vérifie une preuve OR disjonctive pour un bit.

        Contrôles effectués :
          1. Cohérence du défi : c0 + c1 == H(C, R0, R1, label) mod q
          2. Branche 0 : g^s0_1 * h^s0_2 * C^c0  == R0
          3. Branche 1 : g^s1_1 * h^s1_2 * C1^c1 == R1  (C1 = C/g)

        Args:
            proof: Dictionnaire produit par _prove_bit().

        Returns:
            True si les trois contrôles passent, False sinon.
        """
         
        try:
            C    = int(proof["C"])
            R0   = int(proof["R0"])
            R1   = int(proof["R1"])
            c0   = int(proof["c0"])
            c1   = int(proof["c1"])
            s0_1 = int(proof["s0_1"])
            s0_2 = int(proof["s0_2"])
            s1_1 = int(proof["s1_1"])
            s1_2 = int(proof["s1_2"])
            label = proof["label"]

            g_inv = pow(self.g, self.p - 2, self.p)
            C1    = (C * g_inv) % self.p

            c_tot = self.sigma._challenge(C, R0, R1, label)
            if (c0 + c1) % self.q != c_tot:
                return False

            lhs0 = (
                pow(self.g, s0_1, self.p) *
                pow(self.h, s0_2, self.p) *
                pow(C,  c0, self.p)
            ) % self.p
            if lhs0 != R0:
                return False

            lhs1 = (
                pow(self.g, s1_1, self.p) *
                pow(self.h, s1_2, self.p) *
                pow(C1, c1, self.p)
            ) % self.p
            if lhs1 != R1:
                return False

            return True
        except Exception:
            return False

    def prove(self, value: float, lo: float, hi: float) -> Dict[str, Any]:
        """
        Génère une preuve ZK complète que lo <= value < hi.

        Étapes :
          1. Conversion en entiers via facteur d'échelle (pour gérer les décimales)
          2. Calcul de w = v_int - lo_int (valeur décalée, toujours >= 0)
          3. Décomposition binaire de w sur n_bits bits
          4. Engagement de chaque bit : C_i = g^b_i * h^r_i
          5. Calcul de r_w = Σ r_i * 2^i mod q (blinding cohérent)
          6. Calcul de C_w = g^w * h^r_w (engagement global, cohérent avec les bits)
          7. Preuve OR pour chaque bit
          8. Knowledge proof sur (w, r_w) dans C_w

        Args:
            value: La valeur réelle à prouver (ex: 37.25).
            lo:    Borne inférieure de l'intervalle (ex: 0.0).
            hi:    Borne supérieure exclusive (ex: 38.0).

        Returns:
            Dictionnaire contenant toute la preuve ZK sérialisable.

        Raises:
            AssertionError: Si value n'est pas dans [lo, hi).
        """

        scale  = max(_compute_scale(value), _compute_scale(lo), _compute_scale(hi))
        v_int  = int(round(Decimal(str(value)) * scale))
        lo_int = int(round(Decimal(str(lo))    * scale))
        hi_int = int(round(Decimal(str(hi))    * scale))

        assert lo_int <= v_int < hi_int, \
            f"Valeur {value} hors de la plage [{lo}, {hi})"

        w          = v_int - lo_int
        range_size = hi_int - lo_int
        n_bits     = max(8, range_size.bit_length())

        # Décomposition binaire + commitments sur chaque bit
        bits   = [(w >> i) & 1 for i in range(n_bits)]
        bit_Cs = []
        bit_rs = []
        for b in bits:
            C_b, r_b = self.ped.commit(b)
            bit_Cs.append(C_b)
            bit_rs.append(r_b)

        
        # r_w = Σ r_i * 2^i mod q garantit C_w = Π C_i^{2^i} (homomorphisme)
        r_w = sum(bit_rs[i] * (2 ** i) for i in range(n_bits)) % self.q
        C_w = (pow(self.g, w, self.p) * pow(self.h, r_w, self.p)) % self.p

        # Preuves OR pour chaque bit
        bit_proofs = []
        for i, (b, C_b, r_b) in enumerate(zip(bits, bit_Cs, bit_rs)):
            bp = self._prove_bit(b, C_b, r_b, f"bit_{i}")
            bit_proofs.append(bp)

        # Knowledge proof sur (w, r_w) dans C_w
        kp = self.sigma.prove(w, C_w, r_w, f"range_{lo}_{hi}_scale{scale}")

        return {
            "commitment_w":    C_w,
            "lo":              lo,
            "hi":              hi,
            "scale":           scale,
            "n_bits":          n_bits,
            "bit_commitments": bit_Cs,
            "bit_proofs":      bit_proofs,
            "knowledge_proof": kp,
        }

    def verify(self, proof: Dict[str, Any]) -> bool:
        """
        Vérifie une preuve de borne complète.

        Contrôles effectués dans l'ordre :
          1. Bit proofs : chaque C_i engage bien un bit ∈ {0, 1}
          2. Cohérence  : C_w == Π C_i^{2^i} mod p
          3. Knowledge  : le prouveur connaît (w, r_w) tel que C_w = g^w * h^r_w

        Args:
            proof: Dictionnaire produit par prove().

        Returns:
            True si les trois contrôles passent, False sinon.
        """

        try:
            C_w        = int(proof["commitment_w"])
            bit_Cs     = [int(c) for c in proof["bit_commitments"]]
            bit_proofs = proof["bit_proofs"]
            kp         = proof["knowledge_proof"]

            # 1. Chaque bit ∈ {0, 1}
            for bp in bit_proofs:
                if not self._verify_bit(bp):
                    return False

            # 2. Cohérence : C_w == Π C_i^{2^i} mod p
            reconstructed = 1
            for i, C_b in enumerate(bit_Cs):
                reconstructed = (reconstructed * pow(C_b, 2 ** i, self.p)) % self.p
            if reconstructed != C_w:
                return False

            # 3. Knowledge proof sur C_w
            if not self.sigma.verify(kp):
                return False

            return True
        except Exception:
            return False


class BulletproofsHandler:
    """
    Interface haut niveau pour le prédicat médical : température < 38°C.

    Orchestre PedersenCommitment, SigmaProtocol et RangeProofEngine
    pour exposer deux méthodes simples : generate() et verify().

    Usage typique :
        handler = BulletproofsHandler()
        proof   = handler.generate(37.25)   # côté hôpital
        result  = handler.verify(proof)      # côté assureur
    """

    TEMP_LO        = 0.0
    TEMP_THRESHOLD = 38.0

    def __init__(self, p: int = PRIME_P, g: int = 2):
        """
        Initialise le handler avec les paramètres cryptographiques.

        Args:
            p: Nombre premier sûr. Par défaut : RFC 3526 Group 5 (1536 bits).
            g: Générateur du groupe. Par défaut : 2.
        """

        self.pedersen     = PedersenCommitment(p=p, g=g)
        self.sigma        = SigmaProtocol(self.pedersen)
        self.range_engine = RangeProofEngine(self.pedersen, self.sigma)

    def generate(self, temperature: float) -> Dict[str, Any]:
        """
        Génère une preuve ZK que temperature < 38°C.

        Vérifie d'abord que la température satisfait le prédicat,
        puis délègue à RangeProofEngine.prove() et mesure le temps.

        Args:
            temperature: La température réelle du patient (float, précision arbitraire).

        Returns:
            Dictionnaire sérialisable contenant la preuve complète,
            le prédicat et le temps de génération en ms.

        Raises:
            ValueError: Si temperature >= 38.0 ou temperature < 0.0.
        """

        t0 = time.time()
        if not (self.TEMP_LO <= temperature < self.TEMP_THRESHOLD):
            raise ValueError(
                f"Température {temperature}°C ne satisfait pas le prédicat "
                f"(doit être dans [{self.TEMP_LO}, {self.TEMP_THRESHOLD}))"
            )
        proof   = self.range_engine.prove(temperature, self.TEMP_LO, self.TEMP_THRESHOLD)
        elapsed = (time.time() - t0) * 1000
        serializable = _serialize_ints(proof)
        serializable["predicate"]          = f"temperature < {self.TEMP_THRESHOLD}°C"
        serializable["generation_time_ms"] = round(elapsed, 3)
        return serializable

    def verify(self, proof_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Vérifie une preuve ZK reçue (côté assureur).

        Désérialise les entiers, exécute les trois contrôles
        (bit proofs, cohérence, knowledge proof) et mesure le temps.

        Args:
            proof_data: Dictionnaire produit par generate() et transmis par l'hôpital.

        Returns:
            Dictionnaire contenant :
              - is_valid              : bool, résultat global
              - range_proof_valid     : bool, contrôle des bits + cohérence
              - knowledge_proof_valid : bool, contrôle Sigma
              - predicate_satisfied   : bool (== is_valid)
              - verification_time_ms  : float
              - error                 : str ou None
        """

        t0 = time.time()
        try:
            restored = _deserialize_ints(proof_data)
            range_ok = self.range_engine.verify(restored)
            kp       = restored.get("knowledge_proof", {})
            know_ok  = self.sigma.verify(kp)
            elapsed  = (time.time() - t0) * 1000
            is_valid = range_ok and know_ok
            return {
                "is_valid":              is_valid,
                "range_proof_valid":     range_ok,
                "knowledge_proof_valid": know_ok,
                "predicate_satisfied":   is_valid,
                "verification_time_ms":  round(elapsed, 3),
                "error":                 None,
            }
        except Exception as e:
            elapsed = (time.time() - t0) * 1000
            return {
                "is_valid":              False,
                "range_proof_valid":     False,
                "knowledge_proof_valid": False,
                "predicate_satisfied":   False,
                "verification_time_ms":  round(elapsed, 3),
                "error":                 str(e),
            }


# ─── Sérialisation ────────────────────────────────────────────────────────────

def _serialize_ints(obj):
    """
    Convertit récursivement tous les entiers Python en chaînes de caractères.

    Nécessaire car les entiers du groupe (mod p, 1536 bits) dépassent
    la capacité de JSON standard et de certains parseurs JavaScript.

    Args:
        obj: Objet Python quelconque (dict, list, int, float, str...).

    Returns:
        Même structure avec les int remplacés par des str.
    """

    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, dict):
        return {k: _serialize_ints(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialize_ints(i) for i in obj]
    return obj


_FLOAT_KEYS = {"lo", "hi", "generation_time_ms", "verification_time_ms"}
_STR_KEYS   = {"label", "predicate"}


def _deserialize_ints(obj, _key: str = "") -> Any:
    """
    Reconstruit récursivement les types Python depuis un objet JSON désérialisé.

    Règles de conversion :
      - Clés dans _STR_KEYS  → str
      - Clés dans _FLOAT_KEYS→ float
      - Autres chaînes       → int (si possible) puis float (si possible) puis str
      - Listes et dicts      → traités récursivement

    Args:
        obj:  L'objet à reconstruire (issu de json.loads).
        _key: Clé parente (utilisée pour déterminer le type attendu).

    Returns:
        L'objet avec les types Python corrects restaurés.
    """
    
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in _STR_KEYS:
                result[k] = str(v)
            elif k in _FLOAT_KEYS:
                result[k] = float(v) if not isinstance(v, float) else v
            else:
                result[k] = _deserialize_ints(v, k)
        return result
    if isinstance(obj, list):
        return [_deserialize_ints(i, _key) for i in obj]
    if isinstance(obj, str):
        if _key in _FLOAT_KEYS:
            try:
                return float(obj)
            except ValueError:
                return obj
        try:
            return int(obj)
        except ValueError:
            try:
                return float(obj)
            except ValueError:
                return obj
    return obj

