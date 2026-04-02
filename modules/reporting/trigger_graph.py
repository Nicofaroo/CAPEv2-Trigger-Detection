import os
import logging
from graphviz import Digraph
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

class TriggerGraph(Report):
    """
    Genera un gráfico de la línea de tiempo de ejecución de APIs de reconocimiento (Triggers).
    """
    # El orden determina cuándo se ejecuta. Lo ponemos alto para asegurar 
    # que todos los datos de comportamiento ya están procesados.
    order = 9000 

    def run(self, results):
        # 1. Definir qué APIs nos interesan como "Disparadores"
        trigger_apis = [
            "GetSystemInfo", 
            "GetCursorPos", 
            "IsDebuggerPresent",
            "GetTickCount",
            "CheckRemoteDebuggerPresent",
            "DeviceIoControl" # A menudo usado para ver tamaños de disco
        ]

        # Iniciar el lienzo del gráfico
        dot = Digraph(comment='Traza de Ejecucion del Malware', format='png')
        dot.attr(rankdir='TB') # Formato de arriba hacia abajo (Top-Bottom)

        # 2. Extraer los datos de comportamiento del análisis de CAPE
        behavior = results.get("behavior", {})
        processes = behavior.get("processes", [])

        if not processes:
            log.warning("No hay procesos en behavior para generar el grafo de triggers.")
            return

        # 3. Iterar por cada proceso analizado
        for proc in processes:
            proc_name = proc.get("process_name", "Unknown.exe")
            calls = proc.get("calls", [])
            
            if not calls:
                continue

            # Crear el nodo inicial del proceso
            prev_node_id = f"start_{proc['process_id']}"
            dot.node(prev_node_id, f"INICIO\n{proc_name}", shape='Mdiamond', style='filled', fillcolor='lightblue')

            # 4. Rastrear la línea de tiempo
            for call in calls:
                api_name = call["api"]
                
                # Si la llamada es un disparador, la añadimos al árbol
                if api_name in trigger_apis:
                    # Extraer el valor de retorno que forzó la decisión
                    ret_val = call.get("return", "Desconocido")
                    
                    # Crear un ID único para el nodo basado en el tiempo
                    node_id = f"node_{call.get('time', id(call))}"
                    
                    # La etiqueta visual que verá el usuario
                    etiqueta = f"API: {api_name}\nRespuesta (Ret): {ret_val}"
                    
                    # Dibujar nodo y conectar con el anterior
                    dot.node(node_id, etiqueta, shape='box')
                    dot.edge(prev_node_id, node_id)
                    
                    # Avanzar el puntero
                    prev_node_id = node_id

            # Nodo final por proceso
            end_node_id = f"end_{proc['process_id']}"
            dot.node(end_node_id, f"FIN / SALIDA", shape='Msquare', style='filled', fillcolor='lightgrey')
            dot.edge(prev_node_id, end_node_id)

        # 5. Guardar la imagen generada en la carpeta de reportes del análisis
        try:
            output_path = os.path.join(self.reports_path, "trigger_cfg")
            dot.render(output_path, cleanup=True) # Cleanup borra el archivo intermedio y deja solo el PNG
            log.info("Gráfico de Triggers generado exitosamente en %s.png", output_path)
        except Exception as e:
            raise CuckooReportError(f"Error generando el gráfico con Graphviz: {e}")
