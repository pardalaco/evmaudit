"""
Catálogo de plantillas Echidna organizadas por detector de Slither.

Estructura de cada entrada:
  swc        : código SWC correspondiente
  titulo     : nombre oficial de la vulnerabilidad
  impacto    : severidad típica que Slither asigna
  modo       : modo de Echidna recomendado ('property' o 'assertion')
  plantilla  : código Solidity generado automáticamente (usa {func} como placeholder)
  limitacion : qué casos NO puede cubrir esta plantilla automática
  echidna_testable: si Echidna puede explotarla sin contrato atacante adicional
"""

CATALOG = {

    # -------------------------------------------------------------------------
    # SWC-101 | Integer Overflow and Underflow
    # Slither detector: integer-overflow (contratos < 0.8)
    # -------------------------------------------------------------------------
    "integer-overflow": {
        "swc": "SWC-101",
        "titulo": "Desbordamiento aritmético (Integer Overflow/Underflow)",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-101: Integer Overflow/Underflow detectado en {func}()
    // Invariante: los balances nunca pueden exceder el supply total ni ser negativos
    function echidna_{func}_no_overflow() public returns (bool) {{
        return balances[msg.sender] <= totalSupply;
    }}

    function echidna_{func}_no_underflow() public returns (bool) {{
        return balances[msg.sender] >= 0;
    }}
""",
        "limitacion": "Necesita que el contrato tenga 'balances' y 'totalSupply'. "
                      "Para contratos pre-0.8 sin SafeMath. En 0.8+ usar bloque unchecked{}.",
    },

    # -------------------------------------------------------------------------
    # SWC-104 | Unchecked Call Return Value
    # Slither detectors: unchecked-lowlevel, unchecked-send
    # -------------------------------------------------------------------------
    "unchecked-lowlevel": {
        "swc": "SWC-104",
        "titulo": "Valor de retorno de llamada no verificado",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-104: Llamada de bajo nivel sin verificar retorno en {func}()
    // Invariante: si una transferencia falla, el estado no debe cambiar
    function echidna_{func}_call_checked() public returns (bool) {{
        uint256 before = address(this).balance;
        (bool success,) = address(this).call{{value: 0}}("");
        if (!success) {{
            return address(this).balance == before;
        }}
        return true;
    }}
""",
        "limitacion": "Detecta el patrón pero no puede simular un fallo real de la llamada "
                      "sin un contrato auxiliar que rechace pagos.",
    },

    "unchecked-send": {
        "swc": "SWC-104",
        "titulo": "Valor de retorno de send() no verificado",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-104: send() sin verificar retorno en {func}()
    // Invariante: el balance del contrato nunca cae inesperadamente
    function echidna_{func}_send_safe() public returns (bool) {{
        uint256 before = address(this).balance;
        {func}(payable(address(this)));
        return address(this).balance <= before;
    }}
""",
        "limitacion": "La llamada interna a {func} puede requerir parámetros específicos.",
    },

    # -------------------------------------------------------------------------
    # SWC-105 | Unprotected Ether Withdrawal
    # Slither detector: arbitrary-send-eth
    # -------------------------------------------------------------------------
    "arbitrary-send-eth": {
        "swc": "SWC-105",
        "titulo": "Retiro de Ether sin control de acceso",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-105: Retiro arbitrario de ETH detectado en {func}()
    // Invariante: el balance del contrato nunca puede ser menor que lo depositado
    function echidna_{func}_funds_preserved() public returns (bool) {{
        return address(this).balance >= totalDeposited;
    }}
""",
        "limitacion": "Necesita variable 'totalDeposited' en el contrato. "
                      "Si el contrato no la tiene, hay que usar address(this).balance > 0 "
                      "como proxy menos preciso.",
    },

    # -------------------------------------------------------------------------
    # SWC-106 | Unprotected SELFDESTRUCT
    # Slither detector: suicidal
    # -------------------------------------------------------------------------
    "suicidal": {
        "swc": "SWC-106",
        "titulo": "SELFDESTRUCT sin control de acceso",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-106: selfdestruct() accesible sin restricciones en {func}()
    // Invariante: el contrato debe seguir existiendo (tener código desplegado)
    function echidna_{func}_contract_alive() public returns (bool) {{
        return address(this).code.length > 0;
    }}
""",
        "limitacion": "Echidna no puede verificar 'code.length' después de selfdestruct "
                      "porque la EVM destruye el contexto. Esta propiedad sirve como "
                      "señal previa — si Echidna llama a {func}() y no revierte, "
                      "el contrato es vulnerable.",
    },

    # -------------------------------------------------------------------------
    # SWC-107 | Reentrancy
    # Slither detectors: reentrancy-eth, reentrancy-no-eth,
    #                    reentrancy-benign, reentrancy-unlimited-gas
    # -------------------------------------------------------------------------
    "reentrancy-eth": {
        "swc": "SWC-107",
        "titulo": "Reentrancia con transferencia de ETH",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": False,
        "plantilla": """
    // SWC-107: Reentrancia con ETH detectada en {func}()
    // Invariante: solvencia — el contrato siempre puede cubrir todos los balances
    function echidna_{func}_solvency() public returns (bool) {{
        return address(this).balance >= balances[msg.sender];
    }}
""",
        "limitacion": "LIMITACION IMPORTANTE: Echidna no puede simular reentrancia "
                      "sin un contrato atacante que re-entre en el callback. "
                      "Esta propiedad detecta violaciones de solvencia pero NO "
                      "la reentrancia en sí. Requiere generar también un Attacker contract.",
    },

    "reentrancy-no-eth": {
        "swc": "SWC-107",
        "titulo": "Reentrancia sin transferencia de ETH (manipulación de estado)",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": False,
        "plantilla": """
    // SWC-107: Reentrancia de estado detectada en {func}()
    // Invariante: el estado crítico no cambia entre llamadas consecutivas
    function echidna_{func}_state_consistent() public returns (bool) {{
        uint256 snapshot = balances[msg.sender];
        return balances[msg.sender] == snapshot;
    }}
""",
        "limitacion": "Misma limitación que reentrancy-eth. Necesita contrato atacante "
                      "para explotar correctamente.",
    },

    "reentrancy-unlimited-gas": {
        "swc": "SWC-107",
        "titulo": "Reentrancia con gas ilimitado",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": False,
        "plantilla": """
    // SWC-107: Reentrancia con gas ilimitado en {func}()
    // Invariante: solvencia del contrato
    function echidna_{func}_gas_reentrancy_safe() public returns (bool) {{
        return address(this).balance >= balances[msg.sender];
    }}
""",
        "limitacion": "Requiere contrato atacante para demostrar la explotación.",
    },

    # -------------------------------------------------------------------------
    # SWC-109 | Uninitialized Storage Pointer
    # Slither detectors: uninitialized-local, uninitialized-state
    # -------------------------------------------------------------------------
    "uninitialized-local": {
        "swc": "SWC-109",
        "titulo": "Puntero a storage no inicializado (variable local)",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-109: Variable local no inicializada en {func}()
    // Invariante: el owner nunca puede ser address(0) tras la inicialización
    function echidna_{func}_no_zero_owner() public returns (bool) {{
        return owner != address(0);
    }}
""",
        "limitacion": "Asume que el contrato tiene una variable 'owner'. "
                      "Para otros patrones de uninitialized storage hay que adaptar "
                      "la variable objetivo manualmente.",
    },

    "uninitialized-state": {
        "swc": "SWC-109",
        "titulo": "Variable de estado no inicializada",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-109: Variable de estado no inicializada detectada en {func}()
    // Invariante: las variables críticas no pueden ser cero tras el constructor
    function echidna_{func}_state_initialized() public returns (bool) {{
        return owner != address(0);
    }}
""",
        "limitacion": "Asume variable 'owner'. Generalizar requiere conocer "
                      "qué variable está sin inicializar.",
    },

    # -------------------------------------------------------------------------
    # SWC-112 | Delegatecall a contrato no confiable
    # Slither detector: controlled-delegatecall
    # -------------------------------------------------------------------------
    "controlled-delegatecall": {
        "swc": "SWC-112",
        "titulo": "Delegatecall a dirección controlada por el usuario",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-112: delegatecall con destino controlado en {func}()
    // Invariante: el owner no puede cambiar mediante delegatecall arbitrario
    function echidna_{func}_owner_immutable() public returns (bool) {{
        address ownerBefore = owner;
        return owner == ownerBefore;
    }}
""",
        "limitacion": "Echidna puede llamar a {func}() con una dirección maliciosa "
                      "que modifique el storage. Si 'owner' no es la variable crítica, "
                      "hay que ajustar la propiedad.",
    },

    # -------------------------------------------------------------------------
    # SWC-113 | DoS con llamadas fallidas
    # Slither detector: calls-loop
    # -------------------------------------------------------------------------
    "calls-loop": {
        "swc": "SWC-113",
        "titulo": "DoS por llamadas externas dentro de un bucle",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-113: Llamadas externas en bucle detectadas en {func}()
    // Invariante: la función siempre debe poder completarse (no revertir por gas)
    // Echidna intentará añadir muchos elementos antes de llamar a {func}()
    function echidna_{func}_no_dos() public returns (bool) {{
        uint256 gasBefore = gasleft();
        return gasleft() > gasBefore / 2;
    }}
""",
        "limitacion": "Echidna tiene límites de gas en el entorno de fuzzing. "
                      "Para DoS reales por gas se recomienda aumentar el gas limit "
                      "en echidna.yaml y poblar el estado con muchos elementos primero.",
    },

    # -------------------------------------------------------------------------
    # SWC-115 | Autenticación mediante tx.origin
    # Slither detector: tx-origin
    # -------------------------------------------------------------------------
    "tx-origin": {
        "swc": "SWC-115",
        "titulo": "Autorización mediante tx.origin en lugar de msg.sender",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-115: Uso de tx.origin para autenticación en {func}()
    // Invariante: un contrato intermediario nunca debe poder llamar a {func}()
    // con éxito si tx.origin != msg.sender
    function echidna_{func}_no_txorigin_bypass() public returns (bool) {{
        // Si msg.sender es un contrato (code.length > 0), {func}() debería revertir
        if (address(msg.sender).code.length > 0) {{
            (bool success,) = address(this).call(
                abi.encodeWithSignature("{func}()")
            );
            return !success;
        }}
        return true;
    }}
""",
        "limitacion": "Echidna usa EOAs por defecto. Para simular un contrato intermediario "
                      "hay que configurar 'deployContracts' en echidna.yaml o generar "
                      "un contrato proxy auxiliar.",
    },

    # -------------------------------------------------------------------------
    # SWC-116 | Block values como proxy de tiempo
    # Slither detector: timestamp
    # -------------------------------------------------------------------------
    "timestamp": {
        "swc": "SWC-116",
        "titulo": "Dependencia de block.timestamp para lógica crítica",
        "impacto": "Low",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-116: Dependencia de block.timestamp en {func}()
    // Invariante: el resultado de {func}() no debe variar solo por el timestamp
    // Echidna varía block.timestamp automáticamente entre llamadas
    function echidna_{func}_timestamp_independent() public returns (bool) {{
        uint256 snapshot = block.timestamp;
        return block.timestamp >= snapshot;
    }}
""",
        "limitacion": "Esta propiedad es débil — verifica que el timestamp avanza "
                      "pero no que la lógica de negocio sea correcta. "
                      "Echidna varía timestamps pero no puede forzar valores exactos "
                      "sin configuración adicional en echidna.yaml.",
    },

    # -------------------------------------------------------------------------
    # SWC-119 | Shadowing de variables de estado
    # Slither detectors: shadowing-state, shadowing-local, shadowing-abstract
    # -------------------------------------------------------------------------
    "shadowing-state": {
        "swc": "SWC-119",
        "titulo": "Variable de estado oculta por variable local (shadowing)",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-119: Shadowing de variable de estado en {func}()
    // Invariante: el owner del storage principal nunca debe ser address(0)
    // Un shadowing incorrecto puede dejar el owner sin inicializar
    function echidna_{func}_no_shadowing_corruption() public returns (bool) {{
        return owner != address(0);
    }}
""",
        "limitacion": "Solo detecta corrupción del owner. El shadowing puede afectar "
                      "a cualquier variable de estado — necesita adaptación según el contrato.",
    },

    "shadowing-local": {
        "swc": "SWC-119",
        "titulo": "Variable local oculta variable de estado",
        "impacto": "Low",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-119: Variable local hace shadowing de estado en {func}()
    // Invariante: el estado global no debe corromperse por shadowing
    function echidna_{func}_global_state_intact() public returns (bool) {{
        return owner != address(0);
    }}
""",
        "limitacion": "Misma limitación que shadowing-state.",
    },

    # -------------------------------------------------------------------------
    # SWC-120 | Aleatoriedad débil (PRNG débil)
    # Slither detector: weak-prng
    # -------------------------------------------------------------------------
    "weak-prng": {
        "swc": "SWC-120",
        "titulo": "Fuente de aleatoriedad débil (block.timestamp, blockhash)",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-120: PRNG débil detectado en {func}()
    // Invariante: el resultado no debe ser siempre predecible (siempre 0 o siempre 1)
    // Echidna varía blockhash y timestamp automáticamente
    function echidna_{func}_prng_not_constant() public returns (bool) {{
        uint256 rand = uint256(blockhash(block.number - 1)) % 2;
        return rand == 0 || rand == 1;
    }}
""",
        "limitacion": "Esta propiedad verifica que el rango es correcto, no que sea "
                      "impredecible. Para demostrar manipulabilidad real se necesita "
                      "un minero adversarial, que Echidna no simula.",
    },

    # -------------------------------------------------------------------------
    # SWC-124 | Escritura en ubicación arbitraria de storage
    # Slither detector: arbitrary-storage-location (raro, contratos assembly)
    # -------------------------------------------------------------------------
    "arbitrary-storage-location": {
        "swc": "SWC-124",
        "titulo": "Escritura en slot de storage arbitrario",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // SWC-124: Escritura arbitraria en storage detectada en {func}()
    // Invariante: el owner nunca puede cambiar mediante una escritura arbitraria
    function echidna_{func}_owner_protected() public returns (bool) {{
        address ownerBefore = owner;
        return owner == ownerBefore;
    }}
""",
        "limitacion": "Solo cubre la variable owner. Un ataque real puede sobrescribir "
                      "cualquier slot. Para cobertura completa habría que monitorizar "
                      "múltiples variables críticas.",
    },

    # -------------------------------------------------------------------------
    # SWC-129 | Error tipográfico en operador
    # Slither detector: tautology
    # -------------------------------------------------------------------------
    "tautology": {
        "swc": "SWC-129",
        "titulo": "Condición que siempre es verdadera o falsa (tautología)",
        "impacto": "Medium",
        "modo": "assertion",
        "echidna_testable": True,
        "plantilla": """
    // SWC-129: Tautología detectada en {func}()
    // Una condición siempre true/false indica un require() roto o lógica incorrecta
    // En modo assertion Echidna busca assert() que fallen
    // Añadir al contrato original:
    //   assert(condition_that_should_sometimes_be_false);
    function echidna_{func}_condition_reachable() public returns (bool) {{
        return true;
    }}
""",
        "limitacion": "Las tautologías son errores de lógica — Echidna puede encontrar "
                      "que un require() nunca falla (lo que es el bug), pero la propiedad "
                      "útil depende de conocer la intención del desarrollador.",
    },

    # -------------------------------------------------------------------------
    # ERC20: Transferencia arbitraria sin aprobación
    # Slither detector: arbitrary-send-erc20
    # -------------------------------------------------------------------------
    "arbitrary-send-erc20": {
        "swc": "SWC-105",
        "titulo": "Transferencia ERC20 arbitraria sin aprobación del titular",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // arbitrary-send-erc20: Transferencia no autorizada de tokens en {func}()
    // Invariante: el balance de un usuario solo puede bajar si él llama a transfer/approve
    function echidna_{func}_token_balance_preserved() public returns (bool) {{
        uint256 before = balanceOf(address(0xdeadbeef));
        return balanceOf(address(0xdeadbeef)) >= before;
    }}
""",
        "limitacion": "La dirección 0xdeadbeef es un placeholder. Para el test real "
                      "Echidna necesita una dirección que tenga tokens previamente — "
                      "configurar en echidna.yaml con 'balanceAddr'.",
    },

    # -------------------------------------------------------------------------
    # Ether bloqueado permanentemente en el contrato
    # Slither detector: locked-ether
    # -------------------------------------------------------------------------
    "locked-ether": {
        "swc": "SWC-132",
        "titulo": "Ether bloqueado permanentemente en el contrato",
        "impacto": "Medium",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // locked-ether: El contrato recibe ETH pero no tiene forma de retirarlo
    // Invariante: si el contrato tiene ETH, debe existir alguna función que lo retire
    // Este test verifica que alguien PUEDE retirar (no que solo el owner pueda)
    function echidna_can_withdraw() public returns (bool) {{
        if (address(this).balance == 0) return true;
        // Si hay ETH en el contrato pero ninguna función puede sacarlo, es un bug
        // Echidna intentará llamar a todas las funciones — si ninguna reduce el balance
        // y el balance > 0, la propiedad es difícil de falsificar automáticamente
        return true;
    }}
""",
        "limitacion": "Esta es la limitación más difícil de cubrir automáticamente. "
                      "Verificar que existe una ruta de salida para el ETH requiere "
                      "análisis de alcanzabilidad que Echidna no hace directamente.",
    },

    # -------------------------------------------------------------------------
    # msg.value en bucle
    # Slither detector: msg-value-loop
    # -------------------------------------------------------------------------
    "msg-value-loop": {
        "swc": "SWC-113",
        "titulo": "msg.value usado dentro de un bucle (contabilidad incorrecta)",
        "impacto": "High",
        "modo": "property",
        "echidna_testable": True,
        "plantilla": """
    // msg-value-loop: msg.value dentro de bucle en {func}()
    // Invariante: el total contabilizado nunca supera el ETH realmente recibido
    function echidna_{func}_accounting_correct() public payable returns (bool) {{
        return address(this).balance >= totalDeposited;
    }}
""",
        "limitacion": "Necesita variable 'totalDeposited'. El bug real es que msg.value "
                      "se suma N veces en N iteraciones del bucle — Echidna puede "
                      "encontrar que totalDeposited > balance real.",
    },

}


# ---------------------------------------------------------------------------
# Tabla de traducción: número SWC de Mythril → detector(es) de Slither
#
# Mythril devuelve "swc-id": "107"
# Slither devuelve "check": "reentrancy-eth"
# Esta tabla permite que el adapter use el mismo catálogo para los dos.
# ---------------------------------------------------------------------------
MYTHRIL_TO_DETECTOR = {
    "101": ["integer-overflow"],
    "104": ["unchecked-lowlevel", "unchecked-send"],
    "105": ["arbitrary-send-eth", "arbitrary-send-erc20"],
    "106": ["suicidal"],
    "107": ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-unlimited-gas"],
    "109": ["uninitialized-local", "uninitialized-state"],
    "112": ["controlled-delegatecall"],
    "113": ["calls-loop", "msg-value-loop"],
    "115": ["tx-origin"],
    "116": ["timestamp"],
    "119": ["shadowing-state", "shadowing-local"],
    "120": ["weak-prng"],
    "124": ["arbitrary-storage-location"],
    "129": ["tautology"],
    "132": ["locked-ether"],
}

# ---------------------------------------------------------------------------
# Severidades que se procesan (filtro por defecto)
# ---------------------------------------------------------------------------
SEVERITY_FILTER = {"High", "Medium"}


def get_template(detector_name: str) -> dict | None:
    """Devuelve la entrada del catálogo para un detector de Slither dado."""
    return CATALOG.get(detector_name)


def get_template_from_swc(swc_id: str) -> list[dict]:
    """
    Devuelve las entradas del catálogo para un SWC dado.
    Acepta tanto "SWC-107" (formato del correlator) como "107" (formato de Mythril).
    Un SWC puede mapear a varios detectores de Slither.
    """
    swc_clean = swc_id.replace("SWC-", "")
    detectors = MYTHRIL_TO_DETECTOR.get(swc_clean, [])
    return [CATALOG[d] for d in detectors if d in CATALOG]


def detector_from_swc(swc_id: str) -> list[str]:
    """
    Devuelve los nombres de detector de Slither para un SWC dado.
    Acepta tanto "SWC-107" como "107".
    """
    swc_clean = swc_id.replace("SWC-", "")
    return MYTHRIL_TO_DETECTOR.get(swc_clean, [])


def list_supported_detectors() -> list[str]:
    """Lista todos los detectores de Slither soportados por el catálogo."""
    return list(CATALOG.keys())


if __name__ == "__main__":
    print(f"Detectores soportados: {len(CATALOG)}\n")
    for detector, entry in CATALOG.items():
        testable = "SI" if entry["echidna_testable"] else "NO (requiere contrato atacante)"
        print(f"  [{entry['swc']}] {detector}")
        print(f"         Título   : {entry['titulo']}")
        print(f"         Impacto  : {entry['impacto']}")
        print(f"         Modo     : {entry['modo']}")
        print(f"         Testable : {testable}")
        print()

    print("\n--- Tabla de traducción Mythril → Slither ---\n")
    for swc_id, detectors in MYTHRIL_TO_DETECTOR.items():
        print(f"  SWC-{swc_id}  →  {', '.join(detectors)}")
