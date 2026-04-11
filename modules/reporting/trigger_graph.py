import os
import logging
from graphviz import Digraph
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

class TriggerGraph(Report):
    """
    Genera un árbol de decisión vectorial (SVG) de APIs.
    """
    order = 9000 

    # --- BASE DE CONOCIMIENTO ---
    # Clasificación de APIs críticas para malware evasivo (Triggers)
    API_KB = {
        # 1. ANTI-DEBUGGING (Rojo Claro)
        "IsDebuggerPresent": {
            "color": "lightcoral", "has_ghost": True,
            "ghost_label": "Comportamiento Oculto\n(Depurador Evadido)",
            "ghost_logic": lambda ret: "!= 0x00000000" if ret == "0x00000000" else "== 0x00000000"
        },
        "CheckRemoteDebuggerPresent": {
            "color": "lightcoral", "has_ghost": True,
            "ghost_label": "Comportamiento Oculto\n(Depurador Evadido)",
            "ghost_logic": lambda ret: "!= 0x00000000" if ret == "0x00000000" else "== 0x00000000"
        },
        "NtQueryInformationProcess": {
            "color": "lightcoral", "has_ghost": True,
            "ghost_label": "Comportamiento Oculto\n(ProcessDebugPort Evadido)",
            "ghost_logic": lambda ret: "Puerto Detectado" if ret == "0x00000000" else "Sin Puerto"
        },
        "OutputDebugStringA": {
            "color": "lightcoral", "has_ghost": False
        },

        # 2. EVASIÓN POR TIEMPO / STALLING (Morado)
        "Sleep": {
            "color": "plum", "has_ghost": True,
            "ghost_label": "Ejecución Rápida\n(Aceleración de Sandbox)",
            "ghost_logic": lambda ret: "Tiempo Original (Pausa Larga)"
        },
        "NtDelayExecution": {
            "color": "plum", "has_ghost": True,
            "ghost_label": "Ejecución Rápida\n(Aceleración de Sandbox)",
            "ghost_logic": lambda ret: "Tiempo Original"
        },
        "GetTickCount": {
            "color": "plum", "has_ghost": True,
            "ghost_label": "Comportamiento Oculto\n(Detección de Hook de Tiempo)",
            "ghost_logic": lambda ret: "Desplazamiento Temporal Inconsistente"
        },
        "QueryPerformanceCounter": {
            "color": "plum", "has_ghost": False
        },

        # 3. ANTI-VM / HARDWARE CHECKS (Azul Claro)
        "GetSystemInfo": {"color": "lightblue", "has_ghost": False},
        "GetNativeSystemInfo": {"color": "lightblue", "has_ghost": False},
        "GlobalMemoryStatusEx": {
            "color": "lightblue", "has_ghost": True,
            "ghost_label": "Comportamiento Oculto\n(Poca RAM detectada)",
            "ghost_logic": lambda ret: "< 4GB RAM"
        },
        "GetDiskFreeSpaceExW": {
            "color": "lightblue", "has_ghost": True,
            "ghost_label": "Comportamiento Oculto\n(Disco pequeño detectado)",
            "ghost_logic": lambda ret: "< 60GB Disco"
        },
        "DeviceIoControl": {"color": "lightblue", "has_ghost": False},
        "GetSystemMetrics": {"color": "lightblue", "has_ghost": False},

        # 4. INTERACCIÓN HUMANA / UI (Amarillo)
        "GetCursorPos": {"color": "lightyellow", "has_ghost": False},
        "GetAsyncKeyState": {"color": "lightyellow", "has_ghost": False},
        "CountClipboardFormats": {"color": "lightyellow", "has_ghost": False},
        "GetForegroundWindow": {"color": "lightyellow", "has_ghost": False},

        # 5. BÚSQUEDA DE HERRAMIENTAS DE ANÁLISIS (Naranja Claro)
        "FindWindowA": {
            "color": "peachpuff", "has_ghost": True,
            "ghost_label": "Ejecución Evasiva\n(Wireshark/Procmon encontrado)",
            "ghost_logic": lambda ret: "!= 0x00000000" if ret == "0x00000000" else "== 0x00000000"
        },
        "FindWindowW": {
            "color": "peachpuff", "has_ghost": True,
            "ghost_label": "Ejecución Evasiva\n(Herramienta encontrada)",
            "ghost_logic": lambda ret: "!= 0x00000000" if ret == "0x00000000" else "== 0x00000000"
        },
        "CreateToolhelp32Snapshot": {"color": "peachpuff", "has_ghost": False},
        "EnumProcesses": {"color": "peachpuff", "has_ghost": False}
    }

    def run(self, results):
        #Inicializo el grafo en modo SVG
        dot = Digraph(comment='Arbol de Decisiones de Triggers', format='svg')
        #Configuro atributos: de arriba a abajo, fondo blanco y fuente arial
        dot.attr(rankdir='TB', bgcolor='white', fontname='Arial')

        #Extraigo el diccionario behavior de los resultados
        behavior = results.get("behavior", {})
        #Extraigo la lista de procesos dentro de behavior
        processes = behavior.get("processes", [])

        #Compruebo si la lista de procesos esta vacia. Si no hay procesos, termina la ejecucion sin hacer nada.
        if not processes:
            return

        # Categorías de CAPE que siempre queremos dibujar aunque no estén en la KB
        target_categories = ["network", "process", "crypto", "system", "synchronization"]

        #Itero sobre sobre cada proceso, obteniendo su indice y sus datos
        for p_idx, p_data in enumerate(processes):
            proc_name = p_data.get("process_name", "Unknown.exe")
            #Obtengo la lista de llamadas API de este proceso.
            calls = p_data.get("calls", [])
            
            #Si el proceso no tiene llamadas APIs registradas pasa al siguiente ignorando al actual.
            if not calls:
                continue

            # 1. Extraer y filtrar: Solo APIs en la KB o de categorías objetivo
            filtered_calls = []
            #Itero sobre cada llamada API del proceso, obteniendo su nombre y categoría (si existe)
            for call in calls:
                api_name = call["api"]
                api_category = call.get("category", "")
                
                #Si la API esta en la KB o su categoría es una de las objetivo, la añado a la lista filtrada con su valor de retorno y tiempo
                if api_name in self.API_KB or api_category in target_categories:
                    #Obtengo el valor de retorno como string, o "None" si no existe
                    ret_val = str(call.get("return", "None"))
                    #Añado un diccionario con la API, categoría, valor de retorno y tiempo (o ID único) a la lista de llamadas filtradas
                    filtered_calls.append({
                        "api": api_name, 
                        "category": api_category,
                        "return": ret_val, 
                        "time": call.get("time", id(call))
                    })

            #Si después de filtrar no quedan llamadas, paso al siguiente proceso
            if not filtered_calls:
                continue

            # 2. Agrupar repeticiones
            grouped_calls = []
            current_call = filtered_calls[0]
            count = 1

            #Comparo cada llamada filtrada con la actual. Si son iguales (misma API y mismo valor de retorno), incremento el contador.
            for call in filtered_calls[1:]:
                #Si la llamada actual es igual a la anterior (misma API y mismo valor de retorno), incremento el contador de repeticiones.
                if call["api"] == current_call["api"] and call["return"] == current_call["return"]:
                    count += 1
                #Si la llamada actual es diferente a la anterior, guardo la llamada anterior con su contador de repeticiones en la lista de llamadas agrupadas.
                else:
                    current_call["count"] = count
                    grouped_calls.append(current_call)
                    current_call = call
                    count = 1
            current_call["count"] = count
            grouped_calls.append(current_call)

            # 3. Dibujar el Árbol
            # Creo el nodo de INICIO para el proceso actual
            prev_node_id = f"start_{p_data['process_id']}_{p_idx}"
            #Dibujo el nodo de INICIO con el nombre del proceso, forma de cuadrado y color gris claro
            dot.node(prev_node_id, f"INICIO\n{proc_name}", shape='Msquare', style='filled', fillcolor='lightgrey')

            #Itero sobre cada llamada agrupada, obteniendo su indice y sus datos
            for i, g_call in enumerate(grouped_calls):
                #Obtengo el nombre de la API de la llamada agrupada 
                api_name = g_call['api']
                #Genero un ID único para el nodo de esta llamada usando su tiempo (o ID) y el índice del proceso, para asegurar que no haya colisiones entre nodos de diferentes procesos o llamadas repetidas.
                node_id = f"node_{g_call['time']}_{p_idx}"
                #Si la llamada se repite más de una vez, añado un texto adicional al nodo indicando el número de iteraciones entre corchetes. Si solo se ejecuta una vez, no añado nada.
                rep_text = f"\n[{g_call['count']} iteraciones]" if g_call['count'] > 1 else ""
                
                #Asigno un color por defecto basado en la categoría de la llamada, o blanco si no tiene categoría o no está en la KB
                default_colors = {
                    "network": "lightgreen",
                    "process": "orange",
                    "crypto": "violet",
                    "system": "lightcyan",
                    "synchronization": "gainsboro"
                }
                cat_color = default_colors.get(g_call.get('category'), "white")
                
                # Busco la configuración en la Base de Conocimiento
                api_config = self.API_KB.get(api_name, {"color": cat_color, "has_ghost": False})
                
                # Dibujo el nodo de la API (Rombo de decisión)
                dot.node(node_id, f"{api_name}{rep_text}", shape='diamond', style='filled', fillcolor=api_config["color"])
                
                # Conexión con el nodo anterior
                if i == 0:
                    # Si es la primera, conecto directamente con INICIO
                    dot.edge(prev_node_id, node_id)
                else:
                    # Conecto con la llamada anterior usando el valor de retorno real
                    prev_call = grouped_calls[i-1]
                    prev_config = self.API_KB.get(prev_call['api'], {})
                    
                    # Camino Real (Flecha negra gruesa)
                    dot.edge(prev_node_id, node_id, label=f" {prev_call['return']} ", color='black', penwidth='2.0')
                    
                    # RAMA FANTASMA (Evasión): Si la API anterior tiene configurada una rama oculta
                    if prev_config.get("has_ghost"):
                        ghost_id = f"ghost_{prev_call['time']}_{p_idx}"
                        ghost_label = prev_config.get("ghost_label", "Comportamiento Oculto")
                        dot.node(ghost_id, ghost_label, shape='box', style='dashed', color='gray', fontcolor='gray')
                        
                        # Usamos la lógica lambda de la KB para calcular el retorno evadido
                        logic_func = prev_config.get("ghost_logic")
                        alt_return = logic_func(prev_call['return']) if logic_func else "Camino alternativo"
                        
                        # Flecha punteada hacia la rama evadida
                        dot.edge(prev_node_id, ghost_id, label=f" {alt_return} ", style='dashed', color='gray', fontcolor='gray')

                # El nodo actual será el 'prev' en la siguiente iteración
                prev_node_id = node_id

            # Nodo Final (Cierre de la traza del proceso)
            end_node_id = f"end_{p_data['process_id']}_{p_idx}"
            dot.node(end_node_id, "FIN TRAZA", shape='Msquare', style='filled', fillcolor='lightgrey')
            last_call = grouped_calls[-1]
            dot.edge(prev_node_id, end_node_id, label=f" {last_call['return']} ", color='black', penwidth='2.0')

            # Comprobación final: si la última API también era un trigger
            last_config = self.API_KB.get(last_call['api'], {})
            if last_config.get("has_ghost"):
                ghost_id = f"ghost_end_{p_idx}"
                ghost_label = last_config.get("ghost_label", "Comportamiento Oculto")
                dot.node(ghost_id, ghost_label, shape='box', style='dashed', color='gray', fontcolor='gray')
                logic_func = last_config.get("ghost_logic")
                alt_return = logic_func(last_call['return']) if logic_func else "Camino alternativo"
                dot.edge(prev_node_id, ghost_id, label=f" {alt_return} ", style='dashed', color='gray', fontcolor='gray')

        # GUARDADO DEL ARCHIVO
        try:
            # Construimos la ruta en la carpeta de reportes de la tarea en CAPE
            output_path = os.path.join(self.reports_path, "trigger_cfg")
            # Renderizamos a SVG
            dot.render(output_path, cleanup=True)
            log.info(f"[TriggerGraph] Árbol CFG generado en {output_path}.svg")
        except Exception as e:
            log.error(f"[TriggerGraph] Error al generar SVG: {e}")