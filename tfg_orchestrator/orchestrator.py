import subprocess
import re
import time
import sys

class CapeOrchestrator:
    def __init__(self, cape_dir="/opt/CAPEv2"):
        self.cape_dir = cape_dir

    def submit_sample(self, file_path, options=""):
        """Envía una muestra a CAPE usando su herramienta de línea de comandos."""
        print(f"[*] Enviando {file_path} con opciones: '{options}'...")
        
        cmd = ["poetry", "run", "python", "utils/submit.py", file_path]
        if options:
            cmd.extend(["--options", options])

        # Ejecutamos el comando submit de CAPE
        result = subprocess.run(cmd, cwd=self.cape_dir, capture_output=True, text=True)
        
        # Usamos una expresión regular para extraer el ID de la tarea que nos devuelve la terminal
        match = re.search(r'added as task with ID (\d+)', result.stdout)
        if match:
            task_id = match.group(1)
            print(f"[+] Tarea creada con éxito. ID: {task_id}")
            return int(task_id)
        else:
            print("[-] Error al enviar la tarea:")
            print(result.stdout)
            print(result.stderr)
            return None

    def run_campaign(self, file_path):
        """Ejecuta la estrategia de Contra-Evasión lanzando múltiples análisis."""
        print("\n" + "="*50)
        print(" INICIANDO CAMPAÑA DE ORQUESTACIÓN TFG")
        print("="*50)

        # 1. Ejecución Base (Normal)
        print("\n[Fase 1] Lanzando Ejecución Base (Sin manipulación)...")
        task_baseline = self.submit_sample(file_path)

        # 2. Ejecución Forzada (Modo Dios)
        # Aquí le pasamos la opción oculta 'force_debugger=1' que luego leeremos en la máquina virtual
        print("\n[Fase 2] Lanzando Ejecución Manipulada (Forzando IsDebuggerPresent=1)...")
        task_forced = self.submit_sample(file_path, options="force_debugger=1")

        print("\n" + "="*50)
        print("[!] Campaña enviada a CAPE.")
        print(f"ID Baseline: {task_baseline}")
        print(f"ID Forzado:  {task_forced}")
        print("Espera a que terminen en la web, y luego compara sus gráficos SVG.")
        print("="*50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python orchestrator.py <ruta_al_malware>")
        sys.exit(1)
        
    target_file = sys.argv[1]
    orchestrator = CapeOrchestrator()
    orchestrator.run_campaign(target_file)
