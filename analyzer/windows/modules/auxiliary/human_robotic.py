import logging
import time
import traceback
from ctypes import WINFUNCTYPE, byref, c_bool, wintypes
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import KERNEL32, USER32

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

SM_CXSCREEN = 0
SM_CYSCREEN = 1
RESOLUTION = {
    "x": USER32.GetSystemMetrics(SM_CXSCREEN),
    "y": USER32.GetSystemMetrics(SM_CYSCREEN)
}


# Pausa fija entre trazos (sin variabilidad). 
PAUSE_MS = 1000

# Numero de pasos por trazo. 
STEPS_PER_STROKE = 20

# Sleep entre pasos 
STEP_SLEEP_MS = 10

# Distancia fija entre puntos. Sin variabilidad.
STROKE_DISTANCE = 200


def get_cursor_position():
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    return (pt.x, pt.y)


def move_in_straight_line(start_x, start_y, end_x, end_y):
    dx = (end_x - start_x) / STEPS_PER_STROKE
    dy = (end_y - start_y) / STEPS_PER_STROKE

    for i in range(STEPS_PER_STROKE + 1):
        x = int(start_x + dx * i)
        y = int(start_y + dy * i)
        USER32.SetCursorPos(x, y)
        time.sleep(STEP_SLEEP_MS / 1000.0)


class HumanRobotic(Auxiliary, Thread):
    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.options = options
        # Solo se activa con la flag explicita human_robotic=1
        self.enabled = bool(getattr(self.config, "human_windows", True)) and bool(options.get("human_robotic"))
        self.do_run = self.enabled

    def stop(self):
        self.do_run = False

    def run(self):
        if not self.enabled:
            return True
        if self.options.get("nohuman"):
            return True
        try:
            # Defino un patron deliberadamente robotico: las cuatro esquinas
            # de un rectangulo, recorridas en orden. Los angulos entre trazos
            # son de 90 grados (claramente no humanos).
            margin = 100
            corners = [
                (margin, margin),                          # esquina superior izquierda
                (RESOLUTION["x"] - margin, margin),        # esquina superior derecha
                (RESOLUTION["x"] - margin, RESOLUTION["y"] - margin),  # inferior derecha
                (margin, RESOLUTION["y"] - margin),        # inferior izquierda
            ]

            idx = 0
            while self.do_run:
                # Origen: posicion actual del cursor
                start_x, start_y = get_cursor_position()
                # Destino: siguiente esquina del rectangulo
                end_x, end_y = corners[idx % len(corners)]

                # Movimiento en linea recta con velocidad constante
                move_in_straight_line(start_x, start_y, end_x, end_y)

                # Pausa fija entre trazos (sin variabilidad)
                KERNEL32.Sleep(PAUSE_MS)

                idx += 1

        except Exception:
            log.exception(traceback.format_exc())
