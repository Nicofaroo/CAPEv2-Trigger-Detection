import os
import logging
from graphviz import Digraph
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

class TriggerGraph(Report):
    """
    Genera un árbol de decisión vectorial (SVG) de APIs.
    Muestra el camino real (dinámico) y genera ramas hipotéticas para ilustrar los Triggers.
    """
    order = 9000 

    def run(self, results):
        trigger_apis = [
            "GetSystemInfo", "GetCursorPos", "IsDebuggerPresent",
            "GetTickCount", "CheckRemoteDebuggerPresent", "DeviceIoControl"
        ]
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

	#Itero sobre sobre cada proceso, obteniendo su indice y sus datos
        for p_idx, p_data in enumerate(processes):
            proc_name = p_data.get("process_name", "Unknown.exe")
            calls = p_data.get("calls", []) #Obtengo la lista de llamadas API de este proceso.
            
	   #Si el proceso no tiene llamadas APIs registradas pasa al siguiente ignorando al actual.
            if not calls:
                continue

            # 1. Extraer y filtrar
            filtered_calls = []
            for call in calls:
                api_name = call["api"]
                if api_name in trigger_apis:
                    ret_val = str(call.get("return", "None"))
                    filtered_calls.append({
                        "api": api_name, 
                        "return": ret_val, 
                        "time": call.get("time", id(call))
                    })

            if not filtered_calls:
                continue

            # 2. Agrupar repeticiones
            grouped_calls = []
            current_call = filtered_calls[0]
            count = 1

            for call in filtered_calls[1:]:
                if call["api"] == current_call["api"] and call["return"] == current_call["return"]:
                    count += 1
                else:
                    current_call["count"] = count
                    grouped_calls.append(current_call)
                    current_call = call
                    count = 1
            current_call["count"] = count
            grouped_calls.append(current_call)

            # 3. Dibujar el Árbol
            prev_node_id = f"start_{p_data['process_id']}_{p_idx}"
            dot.node(prev_node_id, f"INICIO\n{proc_name}", shape='Msquare', style='filled', fillcolor='lightblue')

            for i, g_call in enumerate(grouped_calls):
                node_id = f"node_{g_call['time']}_{p_idx}"
                rep_text = f"\n[{g_call['count']} iteraciones]" if g_call['count'] > 1 else ""
                
                # Los nodos de API ahora son rombos (Decisiones)
                dot.node(node_id, f"{g_call['api']}{rep_text}", shape='diamond', style='filled', fillcolor='lightyellow')
                
                # Flecha desde el nodo anterior al actual
                if i == 0:
                    dot.edge(prev_node_id, node_id)
                else:
                    prev_call = grouped_calls[i-1]
                    # La flecha lleva el valor de retorno real
                    dot.edge(prev_node_id, node_id, label=f" {prev_call['return']} ", color='black', penwidth='2.0')
                    
                    # MAGIA DEL TFG: Dibujar la rama fantasma (El Trigger evadido)
                    if prev_call['api'] in ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]:
                        ghost_id = f"ghost_{prev_call['time']}_{p_idx}"
                        dot.node(ghost_id, "Comportamiento Oculto\n(Rama Evadida)", shape='box', style='dashed', color='gray', fontcolor='gray')
                        
                        # Si devolvió 0, la rama alternativa es != 0 (y viceversa)
                        alt_return = "!= 0x00000000" if prev_call['return'] == "0x00000000" else "== 0x00000000"
                        dot.edge(prev_node_id, ghost_id, label=f" {alt_return} ", style='dashed', color='gray', fontcolor='gray')

                prev_node_id = node_id

            # Nodo Final
            end_node_id = f"end_{p_data['process_id']}_{p_idx}"
            dot.node(end_node_id, "FIN TRAZA", shape='Msquare', style='filled', fillcolor='lightgrey')
            last_call = grouped_calls[-1]
            dot.edge(prev_node_id, end_node_id, label=f" {last_call['return']} ", color='black', penwidth='2.0')

            # Rama fantasma para el último nodo si era un Trigger
            if last_call['api'] in ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]:
                ghost_id = f"ghost_end_{p_idx}"
                dot.node(ghost_id, "Comportamiento Oculto\n(Rama Evadida)", shape='box', style='dashed', color='gray', fontcolor='gray')
                alt_return = "!= 0x00000000" if last_call['return'] == "0x00000000" else "== 0x00000000"
                dot.edge(prev_node_id, ghost_id, label=f" {alt_return} ", style='dashed', color='gray', fontcolor='gray')

        try:
            output_path = os.path.join(self.reports_path, "trigger_cfg")
            dot.render(output_path, cleanup=True)
            log.info(f"[TriggerGraph] Árbol CFG generado en {output_path}.svg")
        except Exception as e:
            log.error(f"[TriggerGraph] Error al generar SVG: {e}")
