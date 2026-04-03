import os
import logging
from graphviz import Digraph
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

class TriggerGraph(Report):
    """
    Genera un gráfico vectorial (SVG) de la línea de tiempo de ejecución de APIs.
    Filtra repeticiones consecutivas para evitar gráficos gigantes ilegibles.
    """
    order = 9000 

    def run(self, results):
        trigger_apis = [
            "GetSystemInfo", "GetCursorPos", "IsDebuggerPresent",
            "GetTickCount", "CheckRemoteDebuggerPresent", "DeviceIoControl"
        ]

        # CAMBIO CLAVE: Formato SVG y fondo blanco forzado
        dot = Digraph(comment='Traza de Ejecucion del Malware', format='svg')
        dot.attr(rankdir='TB', bgcolor='white', fontname='Arial')

        behavior = results.get("behavior", {})
        processes = behavior.get("processes", [])

        if not processes:
            return

        for proc in enumerate(processes):
            p_idx, p_data = proc
            proc_name = p_data.get("process_name", "Unknown.exe")
            calls = p_data.get("calls", [])
            
            if not calls:
                continue

            prev_node_id = f"start_{p_data['process_id']}_{p_idx}"
            dot.node(prev_node_id, f"INICIO: {proc_name} (PID: {p_data['process_id']})", 
                     shape='Mdiamond', style='filled', fillcolor='lightblue')

            # Anti-ruido: Control de repeticiones
            last_api = None
            last_ret = None

            for call in calls:
                api_name = call["api"]
                
                if api_name in trigger_apis:
                    ret_val = str(call.get("return", "None"))
                    
                    # Si es la misma API con el mismo resultado, saltamos (Deduplicación)
                    if api_name == last_api and ret_val == last_ret:
                        continue
                    
                    node_id = f"node_{call.get('time', id(call))}_{p_idx}"
                    etiqueta = f"API: {api_name}\nRetorno: {ret_val}"
                    
                    dot.node(node_id, etiqueta, shape='box', style='filled', fillcolor='white')
                    dot.edge(prev_node_id, node_id)
                    
                    prev_node_id = node_id
                    last_api = api_name
                    last_ret = ret_val

            end_node_id = f"end_{p_data['process_id']}_{p_idx}"
            dot.node(end_node_id, "FIN DE TRAZA", shape='Msquare', style='filled', fillcolor='lightgrey')
            dot.edge(prev_node_id, end_node_id)

        try:
            output_path = os.path.join(self.reports_path, "trigger_cfg")
            dot.render(output_path, cleanup=True)
            log.info(f"[TriggerGraph] Grafo SVG generado en {output_path}.svg")
        except Exception as e:
            log.error(f"[TriggerGraph] Error al generar SVG: {e}")
