#Importo la clase base Processing de CAPE. Esto va a ser un modulo processing, es decir,
#que se ejecuta despeusd del analisis dinamico. Cuando ya tiene datos recogidos.
from lib.cuckoo.common.abstracts import Processing

#Defino la clase nueva llamada TriggerProfiler que hereda de Processign.
class TriggerProfiler(Processing):
    #Defino este modulo como el ultimo en ejecutarse en processing.
    order = 99

    #Funcion de proteccion. Si value es realmente una lista, la devuelve tal cual.
    #Sino devuelve una lista vacia.
    def _safe_list(self, value):
        return value if isinstance(value, list) else []

    #Aqui extraigo los nombres de las APIs observadas.En CAPE, dentro de 
    #behaviour.process[].calls[] se registran llamadas del programa a APIs de Windows
    def _collect_api_names(self, behavior, max_calls=8000):
        apis = []
        total = 0

	#Obtengo la lista de procesos del bloque behaviour.
        processes = self._safe_list(behavior.get("processes", []))

	#Recorro cada proceso y para cada uno obtengo su lista de llamadas API.
        for proc in processes:
            calls = self._safe_list(proc.get("calls", []))

	    #Para cada llamada, cojo el nombre, lo convierto a string, lo paso a
	    #mayusculas y le quito los espacios
            for call in calls:
                api = str(call.get("api", "")).lower().strip()
                if api:
                    apis.append(api)
                total += 1
                if total >= max_calls:
                    return apis

	#Devuelvo la lista completa de APIs recogidas.
        return apis

    #Defino una lista de claves de bloques network que considero relevantes
    def _network_present(self, network):
        interesting = [
            "dns", "http", "https", "tcp", "udp", "icmp",
            "smtp", "irc", "hosts", "domains", "tls"
        ]

	#Reviso una a una esas claves. Si contienen una lista no vacia o un diccionario no vacio
	#entonces significa que si ha habido actividad de red.
        for key in interesting:
            value = network.get(key)
            if isinstance(value, list) and value:
                return True
            if isinstance(value, dict) and value:
                return True
        return False

    #Funcion central. Sirve para encontrar coincidencias entre una lista de cadenas values y
    #un conjunto de patrones needles
    def _count_matches(self, values, needles):
        count = 0

	#Recorro cada valor v y compruebo si contiene alguno de los patrones n.
        for v in values:
            for n in needles:
                if n in v:
                    count += 1
                    break

	#Devuelvo cuantos elementos han coincidido.
        return count

    #Version booleana de la anterior. Devuelve true si hay al menos una coincidencia.
    def _any_match(self, values, needles):
        return self._count_matches(values, needles) > 0

    #Redondea una puntuacion a tres decimales y limita a un mazimo de 1.0
    def _cap(self, x, maxv=1.0):
        return min(round(x, 3), maxv)

    #Aqui defino la funcion principal del modulo.
    def run(self):

	#Primero le digo a CAPE que el resultado de este modulo se guradara bajo esta clave.
        self.key = "trigger_profile"

	#Defuno la estructura de los resultados. Inicializo la decision global junto a las
	#cinco categorias de triggers. Cada categoria tendra su propia lista de evidencias.
        results = {
            "suspected": False,
            "primary": None,
            "secondary": None,
            "scores": {
                "time": 0.0,
                "environment": 0.0,
                "user_interaction": 0.0,
                "network": 0.0,
                "logic": 0.0,
            },
            "evidence": {
                "time": [],
                "environment": [],
                "user_interaction": [],
                "network": [],
                "logic": [],
            },
            "notes": [
                "Heuristic classifier based on CAPE report artifacts",
                "Logical triggers are inferred with lower confidence than the rest",
            ],
        }

	#Aqui recojo distintas partes del informe generado por cape
	#Signatures - firmas detectadas por CAPE
	#Behavior - bloque general del comportamiento
	#Summary - resumen del comportamiento
	#Network - actividad de red
	#Info - metadatos del analisis
        signatures = self._safe_list(self.results.get("signatures", []))
        behavior = self.results.get("behavior", {}) or {}
        summary = behavior.get("summary") or {}
        network = self.results.get("network", {}) or {}
        info = self.results.get("info", {}) or {}

	#Construyo un conjutno set con los nombres de las firmas en minuscula
        sig_names = {
            str(sig.get("name", "")).lower()
            for sig in signatures
            if isinstance(sig, dict)
        }

	#Llamo a la funcion auxiliar para obtener todas las APIs observadas del bloqeu de comportamiento
        api_names = self._collect_api_names(behavior)

	#Cojo listas del resumen, las convierto a listas seguras, luego a string y paso todo a minusculas
        files = [str(x).lower() for x in self._safe_list(summary.get("files", []))]
        read_files = [str(x).lower() for x in self._safe_list(summary.get("read_files", []))]
        write_files = [str(x).lower() for x in self._safe_list(summary.get("write_files", []))]
        delete_files = [str(x).lower() for x in self._safe_list(summary.get("delete_files", []))]
        keys = [str(x).lower() for x in self._safe_list(summary.get("keys", []))]
        read_keys = [str(x).lower() for x in self._safe_list(summary.get("read_keys", []))]
        write_keys = [str(x).lower() for x in self._safe_list(summary.get("write_keys", []))]
        delete_keys = [str(x).lower() for x in self._safe_list(summary.get("delete_keys", []))]
        executed_commands = [str(x).lower() for x in self._safe_list(summary.get("executed_commands", []))]
        mutexes = [str(x).lower() for x in self._safe_list(summary.get("mutexes", []))]

	#Aqui decido si hay actividad de red relevante.
        has_network = self._network_present(network)
        low_activity = (
            not has_network
            and len(write_files) == 0
            and len(delete_files) == 0
            and len(write_keys) == 0
            and len(delete_keys) == 0
        )

        # -----------------------------
        # 1. TIME-BASED TRIGGERS
        # -----------------------------
        time_api_needles = {
            "sleep", "sleepex", "ntdelayexecution",
            "waitforsingleobject", "waitformultipleobjects",
            "gettickcount", "gettickcount64",
            "queryperformancecounter", "timegettime",
            "getsystemtime", "getlocaltime", "getsystemtimeasfiletime"
        }

        time_cmd_needles = {
            "timeout ", "ping -n", "start-sleep", "sleep "
        }

	#Firmas con sleep o delay
        if self._any_match(sig_names, {"sleep", "delay"}):
            results["scores"]["time"] += 0.45
            results["evidence"]["time"].append("Sleep or delay-related signature matched")

	#APIs temporales
        time_api_count = self._count_matches(api_names, time_api_needles)
        if time_api_count >= 1:
            results["scores"]["time"] += 0.20
            results["evidence"]["time"].append(f"Observed time-related APIs ({time_api_count} matches)")
        if time_api_count >= 4:
            results["scores"]["time"] += 0.15
            results["evidence"]["time"].append("Multiple time-check or delay APIs observed")

	#Comandos de delay
        if self._any_match(executed_commands, time_cmd_needles):
            results["scores"]["time"] += 0.25
            results["evidence"]["time"].append("Command-line delay primitive observed")

	#Duracion larga con poca actividad
        duration = info.get("duration")
        if isinstance(duration, (int, float)) and duration > 180 and low_activity:
            results["scores"]["time"] += 0.10
            results["evidence"]["time"].append("Long execution with very limited activity")

        results["scores"]["time"] = self._cap(results["scores"]["time"])

        # -----------------------------
        # 2. ENVIRONMENT-BASED TRIGGERS
        # -----------------------------
        env_sig_needles = {
            "antivm", "antisandbox", "antiemu", "antiav", "antidebug"
        }

        env_api_needles = {
            "getkeyboardlayout", "getkeyboardlayoutlist",
            "getuserdefaultlangid", "getuserdefaultuilanguage",
            "getsystemdefaultlangid", "getlocaleinfo",
            "getcomputername", "getusername",
            "wmienum", "iwbemservices", "coqueryproxyblanket",
            "isprocessorfeaturepresent", "getsysteminfo", "ntquerysysteminformation"
        }

        vm_needles = {
            "vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
            "parallels", "sandboxie", "wine", "virtu"
        }

        hw_needles = {
            "hardware\\description\\system\\bios",
            "hardware\\description\\system\\centralprocessor",
            "{4d36e968-e325-11ce-bfc1-08002be10318}",
            "driverversion", "driverdesc", "usermodedrivername"
        }

        if self._any_match(sig_names, env_sig_needles):
            results["scores"]["environment"] += 0.45
            results["evidence"]["environment"].append("Environment-evasion signature matched")

        env_api_count = self._count_matches(api_names, env_api_needles)
        if env_api_count >= 1:
            results["scores"]["environment"] += 0.15
            results["evidence"]["environment"].append(f"Observed environment-enumeration APIs ({env_api_count} matches)")

        if self._any_match(keys + read_keys + files, vm_needles):
            results["scores"]["environment"] += 0.25
            results["evidence"]["environment"].append("VM or sandbox-related artifacts queried")

        if self._any_match(keys + read_keys, hw_needles):
            results["scores"]["environment"] += 0.15
            results["evidence"]["environment"].append("BIOS/CPU/GPU-related registry probing observed")

        if self._any_match(sig_names, {"keyboard_layout", "queries_keyboard_layout"}):
            results["scores"]["environment"] += 0.10
            results["evidence"]["environment"].append("Keyboard layout queried")

        results["scores"]["environment"] = self._cap(results["scores"]["environment"])

        # -----------------------------
        # 3. USER-INTERACTION TRIGGERS
        # -----------------------------
        user_sig_needles = {
            "mouse", "keyboard", "foregroundwindow", "getlastinputinfo",
            "mousemovement", "mouse_hook", "click"
        }

        user_api_needles = {
            "getcursorpos", "setcursorpos", "getasynckeystate", "getkeystate",
            "getkeyboardstate", "getlastinputinfo", "getforegroundwindow",
            "sendinput", "mouse_event", "keybd_event", "setwindowshookex",
            "registerrawinputdevices", "blockinput"
        }

        if self._any_match(sig_names, user_sig_needles):
            results["scores"]["user_interaction"] += 0.45
            results["evidence"]["user_interaction"].append("User-interaction related signature matched")

        user_api_count = self._count_matches(api_names, user_api_needles)
        if user_api_count >= 1:
            results["scores"]["user_interaction"] += 0.25
            results["evidence"]["user_interaction"].append(f"Observed user-interaction APIs ({user_api_count} matches)")

        if user_api_count >= 3 and low_activity:
            results["scores"]["user_interaction"] += 0.15
            results["evidence"]["user_interaction"].append("Interaction checks observed with otherwise limited activity")

        results["scores"]["user_interaction"] = self._cap(results["scores"]["user_interaction"])

        # -----------------------------
        # 4. NETWORK-BASED TRIGGERS
        # -----------------------------
        net_sig_needles = {
            "dead_connect", "dead_link", "network_", "http_", "dns_", "tls_"
        }

        net_api_needles = {
            "connect", "wsastartup", "send", "recv", "internetopen",
            "internetconnect", "internetopenurl", "httpsendrequest",
            "winhttpopen", "winhttpconnect", "winhttpsendrequest",
            "dnsquery", "getaddrinfo", "gethostbyname"
        }

        cert_api_needles = {
            "winverifytrust", "certopenstore", "certgetcertificatechain",
            "certverifycertificatechainpolicy", "cryptqueryobject"
        }

        if has_network:
            results["scores"]["network"] += 0.20
            results["evidence"]["network"].append("Observed network activity in report")

        if self._any_match(sig_names, net_sig_needles):
            results["scores"]["network"] += 0.20
            results["evidence"]["network"].append("Network-related signature matched")

        net_api_count = self._count_matches(api_names, net_api_needles)
        if net_api_count >= 1:
            results["scores"]["network"] += 0.20
            results["evidence"]["network"].append(f"Observed network-related APIs ({net_api_count} matches)")

        cert_api_count = self._count_matches(api_names, cert_api_needles)
        if has_network and cert_api_count >= 1:
            results["scores"]["network"] += 0.15
            results["evidence"]["network"].append("Certificate or trust validation used alongside network activity")

        if has_network and low_activity:
            results["scores"]["network"] += 0.15
            results["evidence"]["network"].append("Network activity observed with very limited local side effects")

        results["scores"]["network"] = self._cap(results["scores"]["network"])

        # -----------------------------
        # 5. LOGIC-BASED TRIGGERS
        # -----------------------------
        logic_api_needles = {
            "getcommandline", "commandlinetoargvw",
            "getenvironmentvariable", "expandenvironmentstrings",
            "getfileattributes", "findfirstfile", "findnextfile",
            "regopenkey", "regqueryvalue", "regqueryinfokey",
            "openmutex", "createmutex"
        }

        read_volume = len(read_keys) + len(read_files) + len(files)
        write_volume = len(write_keys) + len(write_files) + len(delete_keys) + len(delete_files)

        logic_api_count = self._count_matches(api_names, logic_api_needles)
        if logic_api_count >= 1:
            results["scores"]["logic"] += 0.20
            results["evidence"]["logic"].append(f"Observed conditional-check APIs ({logic_api_count} matches)")

        if read_volume >= 20 and write_volume == 0 and not has_network:
            results["scores"]["logic"] += 0.25
            results["evidence"]["logic"].append("Heavy read/check activity with no visible follow-up actions")

        if len(mutexes) > 0 and low_activity:
            results["scores"]["logic"] += 0.10
            results["evidence"]["logic"].append("Mutex usage observed with otherwise limited behavior")

        if (
            results["scores"]["time"] < 0.4
            and results["scores"]["environment"] < 0.4
            and results["scores"]["user_interaction"] < 0.4
            and results["scores"]["network"] < 0.4
            and low_activity
            and (read_volume >= 10 or logic_api_count >= 2)
        ):
            results["scores"]["logic"] += 0.20
            results["evidence"]["logic"].append("Candidate hidden logical gate inferred from low-activity checking pattern")

        results["scores"]["logic"] = self._cap(results["scores"]["logic"])

        # -----------------------------
        # GLOBAL DECISION
        # -----------------------------
        ordered = sorted(
            results["scores"].items(),
            key=lambda kv: kv[1],
            reverse=True
        )

        primary_name, primary_score = ordered[0]
        secondary_name, secondary_score = ordered[1]

        if primary_score >= 0.5:
            results["suspected"] = True
            results["primary"] = primary_name

        if secondary_score >= 0.35:
            results["secondary"] = secondary_name

        return results
