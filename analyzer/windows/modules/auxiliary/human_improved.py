#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# human_improved.py - Modulo auxiliar de interaccion humana mejorado para CAPEv2
#
# TFG: Identificacion y simulacion de triggers de interaccion humana en
#      analisis dinamico de malware.
# Autor: Nicolas Fabra (Universidad de Zaragoza)
#
# OBJETIVO
# --------
# El modulo "human.py" original de CAPE mueve el raton a destinos aleatorios
# con pausas de 1000 ms y deja el cursor inmovil el 25% del tiempo. Esto es
# suficiente para sandboxes que solo comprueban "hay algun movimiento?", pero
# NO para malware que analiza la GEOMETRIA ESTADISTICA del movimiento.
#
# Casos que el modulo original NO supera (verificado experimentalmente):
#   * Gozi/Ursnif : muestrea GetCursorPos cada 64 ms (WaitForSingleObject 0x40)
#                   y usa el delta XOR de coordenadas como semilla de descifrado.
#                   Con Sleep(1000) la mayoria de deltas son 0.
#                   (Forcepoint 2017; Joe Security 2018)
#   * LummaC2 v4.0: captura 5 posiciones a intervalos de 50 ms, las trata como
#                   vectores euclideos y exige que TODOS los angulos entre
#                   vectores consecutivos sean < 45 grados. Los saltos bruscos
#                   del Bezier original generan angulos > 45.
#                   (Outpost24 / KrakenLabs 2023)
#
# FUNDAMENTO TEORICO
# ------------------
#   * Flash & Hogan (1985): modelo de minimo jerk. El movimiento humano de
#     alcance sigue un perfil de velocidad en campana, con velocidad y
#     aceleracion nulas en inicio y fin. Funcion: f(t)=10t^3-15t^4+6t^5.
#   * Fitts (1954): la duracion del movimiento crece con la distancia.
#   * Check Point Research (2025): los sandboxes que mueven el raton a una
#     posicion aleatoria nueva cada segundo (random walk) son detectables por
#     sus anomalias estadisticas. La defensa es movimiento CONTINUO y suave.
#
# IDEA CENTRAL
# ------------
# Para enganar a LummaC2 no imitamos al humano REAL (que hace overshoots y
# giros bruscos), sino el MODELO de humano que el malware asume: movimiento
# suave con cambios de direccion graduales (< 45 grados). Conformamos el
# movimiento al criterio del detector. Este es precisamente el punto debil
# estadistico que describe Check Point.
#
# ACTIVACION
# ----------
# Se activa unicamente con la opcion de submit:  human_improved=1
# El modulo original (human.py) se autodesactiva cuando esa flag esta presente,
# de modo que solo uno de los dos actua en cada analisis. Condiciones de
# experimentacion disponibles:
#     nohuman=1          -> sin ningun modulo
#     (sin flag)         -> human.py original
#     human_improved=1   -> este modulo
# ---------------------------------------------------------------------------

import contextlib
import logging
import math
import random
import time
import traceback
from ctypes import WINFUNCTYPE, byref, c_bool, c_size_t, create_unicode_buffer, memmove, sizeof, wintypes
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import (
    BM_CLICK,
    BM_GETCHECK,
    BM_SETCHECK,
    BST_CHECKED,
    GMEM_MOVEABLE,
    KERNEL32,
    USER32,
    WM_CLOSE,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
)

# Logger para el modulo. Los mensajes aparecen en analysis.log con el prefijo "human_improved"
log = logging.getLogger(__name__)

# Tipos de callback para EnumWindows y EnumChildWindows
EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
EnumChildProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

# Constantes de resolucion de pantalla y clipboard
SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_CXFULLSCREEN = 16
SM_CYFULLSCREEN = 17

# Resolucion de la pantalla. Se obtiene al iniciar el modulo para adaptarse a cualquier pantalla.
# Se usa para calcular detinos del cursosr y evitar salirse de la pantalla.
RESOLUTION = {"x": USER32.GetSystemMetrics(SM_CXSCREEN), "y": USER32.GetSystemMetrics(SM_CYSCREEN)}

# Resolucion sin barra de tareas. Se usa para calcular destinos del cursor y evitar que queden ocultos.
RESOLUTION_WITHOUT_TASKBAR = {"x": USER32.GetSystemMetrics(SM_CXFULLSCREEN), "y": USER32.GetSystemMetrics(SM_CYFULLSCREEN)}

# Lista de vetanas visibles al iniciar el modulo.
# Se usa para cambiar aleatoriamente la ventana de primer plano.
INITIAL_HWNDS = []

# Formato de texto Unicode para el portapapeles.
CF_UNICODETEXT = 0x000D

# ---------------------------------------------------------------------------
# PARAMETROS DEL MODELO DE MOVIMIENTO
# ---------------------------------------------------------------------------
# Intervalo entre actualizaciones de posicion. Debe ser MUY inferior al ritmo
# de muestreo del malware (50 ms Lumma, 64 ms Gozi) para que cada muestra que
# tome el malware capte movimiento real y continuo.
STEP_MIN_MS = 12
STEP_MAX_MS = 18

# Giro maximo permitido entre trazos consecutivos. LummaC2 exige < 45 grados;
# usamos 18 para dejar margen frente a la desviacion que introduce la curvatura
# de Bezier en los extremos del trazo.
MAX_TURN_DEG = 18.0

# Curvatura del trazo (offset del punto de control como fraccion de la
# distancia). Pequena para que la trayectoria sea natural sin generar giros
# bruscos. atan(2*0.07) ~ 8 grados de desviacion maxima de la tangente.
CURVE_K_MAX = 0.07

# Rango de distancia de cada trazo en pixeles.
STROKE_DIST_MIN = 80
STROKE_DIST_MAX = 400

# Duracion del trazo (ley de Fitts simplificada): base + proporcional a la
# distancia, con ruido gaussiano. Acotada a un rango plausible.
DUR_BASE_S = 0.28
DUR_PER_PX_S = 1.0 / 900.0
DUR_MIN_S = 0.28
DUR_MAX_S = 1.20

# Margen respecto a los bordes de pantalla.
EDGE_MARGIN = 12

CLICK_BUTTONS = (
    "yes", "ok", "accept", "next", "install", "run", "agree", "enable", "retry",
    "don't send", "don't save", "continue", "connect", "unzip", "open",
    "close the program", "save", "later", "finish", "end", "keep",
    "allow access", "remind me later",
    "ja", "weiter", "akzeptieren", "ende", "starten", "jetzt starten",
    "neustarten", "neu starten", "jetzt neu starten", "beenden", "oeffnen",
    "schliessen", "installation weiterfuhren", "fertig", "fortsetzen",
    "fortfahren", "stimme zu", "zustimmen", "senden", "nicht senden",
    "speichern", "nicht speichern", "ausfuehren", "spaeter", "einverstanden",
    "установить",
)

DONT_CLICK_BUTTONS = (
    "check online for a solution",
    "don't ask me again for remote connections from this publisher",
    "don't run", "do not ask again until the next update is available",
    "cancel", "do not accept the agreement",
    "i would like to help make reader even better", "restart now",
    "abbrechen", "online nach losung suchen", "abbruch", "nicht ausfuehren",
    "hilfe", "stimme nicht zu",
    "приoстановить", "отмена",
)

OFFICE_WINDOW_CLASSES = ("nuidialog", "bosa_sdm_msword")

KERNEL32.GlobalAlloc.argtypes = [wintypes.UINT, c_size_t]
KERNEL32.GlobalAlloc.restype = wintypes.HGLOBAL
KERNEL32.GlobalLock.argtypes = [wintypes.HGLOBAL]
KERNEL32.GlobalLock.restype = wintypes.LPVOID
KERNEL32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
KERNEL32.GlobalUnlock.restype = wintypes.BOOL
USER32.OpenClipboard.argtypes = [wintypes.HWND]
USER32.OpenClipboard.restype = wintypes.BOOL
USER32.EmptyClipboard.argtypes = []
USER32.EmptyClipboard.restype = wintypes.BOOL
USER32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
USER32.SetClipboardData.restype = wintypes.HANDLE
USER32.CloseClipboard.argtypes = []
USER32.CloseClipboard.restype = wintypes.BOOL


# ===========================================================================
# FUNCIONES AUXILIARES DE INTERACCION CON EL SISTEMA
# ===========================================================================

# Obtengo la posicion actual del cursor.
def get_cursor_position():
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    return (pt.x, pt.y)

# Compruebo si el cursor esta sobre una ventana de consola (cmd.exe, powershell). 
def cursor_over_console_window():
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    hwnd = USER32.WindowFromPoint(pt)
    if not hwnd or not USER32.IsWindowVisible(hwnd):
        return False
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    return "ConsoleWindowClass" in str(classname_ptr.value)


def get_window_text(hwnd):
    length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    if length == 0:
        return ""
    text = create_unicode_buffer(length + 1)
    USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)
    return text.value.replace("&", "")


def is_button_checked(hwnd):
    return bool(USER32.SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED)


def send_click(hwnd):
    USER32.SetForegroundWindow(hwnd)
    KERNEL32.Sleep(200)
    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)


def click_button(hwnd, classname):
    button_text = get_window_text(hwnd)
    if button_text == "" or not USER32.IsWindowEnabled(hwnd):
        return True
    if "Microsoft" in button_text and classname in OFFICE_WINDOW_CLASSES:
        USER32.SetForegroundWindow(hwnd)
        USER32.keybd_event(0x0D, 0x1C, 0, 0)
        USER32.keybd_event(0x0D, 0x1C, 2, 0)
        return False
    button_text = button_text.lower()
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]:
        return True
    if [t for t in CLICK_BUTTONS if t in button_text]:
        log.info('Found button "%s", clicking it', button_text)
        send_click(hwnd)
        return False
    return True


def check_button(hwnd):
    if is_button_checked(hwnd):
        return True
    button_text = get_window_text(hwnd).lower()
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]:
        return True
    if [t for t in CLICK_BUTTONS if t in button_text]:
        send_click(hwnd)
        if not is_button_checked(hwnd):
            USER32.SendMessageW(hwnd, BM_SETCHECK, BST_CHECKED, 0)
        return False
    return True


def is_button(classname):
    return bool("button" in classname or classname in OFFICE_WINDOW_CLASSES)


def interact_with_window(hwnd, lparam):
    if not USER32.IsWindowVisible(hwnd):
        return True
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    classname = str(classname_ptr.value).lower()
    if "checkbox" in classname or "radiobutton" in classname:
        return check_button(hwnd)
    elif is_button(classname):
        return click_button(hwnd, classname)
    return True


def handle_window_interaction(hwnd, lparam):
    interact_with_window(hwnd, lparam)
    USER32.EnumChildWindows(hwnd, EnumChildProc(interact_with_window), 0)
    return True


def get_window_list(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd):
        INITIAL_HWNDS.append(hwnd)
    return True


def get_document_window(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        if any(v in text.value for v in ("- Microsoft", "- Word", "- Excel",
                                         "- PowerPoint", "- Adobe", "- Acrobat",
                                         "- Reader", "- PDF")):
            log.info("Closing document window")
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None)
    return True


def click_mouse():
    USER32.mouse_event(2, 0, 0, 0, None)  # left down
    KERNEL32.Sleep(50)
    USER32.mouse_event(4, 0, 0, 0, None)  # left up


def populate_clipboard():
    randchars = list("   aaaabcddeeeeeefghhhiiillmnnnooooprrrsssttttuwy")
    cliplen = random.randint(10, 1000)
    clipstr = "".join(randchars[random.randint(0, len(randchars) - 1)] for _ in range(cliplen))
    cliprawstr = create_unicode_buffer(clipstr)
    if not USER32.OpenClipboard(None):
        return
    try:
        USER32.EmptyClipboard()
        buf = KERNEL32.GlobalAlloc(GMEM_MOVEABLE, sizeof(cliprawstr))
        if not buf:
            return
        lockbuf = KERNEL32.GlobalLock(buf)
        if not lockbuf:
            return
        memmove(lockbuf, cliprawstr, sizeof(cliprawstr))
        KERNEL32.GlobalUnlock(buf)
        USER32.SetClipboardData(CF_UNICODETEXT, buf)
    finally:
        USER32.CloseClipboard()


# ---------------------------------------------------------------------------
# MOTOR DE MOVIMIENTO HUMANO
# ---------------------------------------------------------------------------

def _min_jerk(tau):
    """Factor de interpolacion de minimo jerk (Flash & Hogan, 1985).

    Para tau en [0,1] devuelve un valor en [0,1] cuya derivada (velocidad)
    tiene forma de campana, con velocidad y aceleracion nulas en los extremos.
    Es el modelo aceptado del movimiento humano de alcance.
    """
    if tau <= 0.0:
        return 0.0
    if tau >= 1.0:
        return 1.0
    return 10.0 * tau ** 3 - 15.0 * tau ** 4 + 6.0 * tau ** 5


def _ang_diff(a, b):
    """Diferencia angular b-a normalizada al rango [-pi, pi]."""
    d = (b - a) % (2.0 * math.pi)
    if d > math.pi:
        d -= 2.0 * math.pi
    return d


class _MovementState:
    """Estado del cursor: posicion actual y rumbo (heading) del ultimo trazo.

    Mantener el rumbo permite restringir el giro entre trazos consecutivos por
    debajo de MAX_TURN_DEG, que es lo que exige el filtro trigonometrico de
    LummaC2 (todos los angulos < 45 grados).
    """

    def __init__(self):
        x, y = get_cursor_position()
        self.x = float(x)
        self.y = float(y)
        self.heading = None  # radianes; None hasta el primer trazo


def _pick_next_target(state):
    """Elige el siguiente destino con un giro <= MAX_TURN_DEG respecto al rumbo.

    Cerca de los bordes, dirige gradualmente el rumbo hacia el centro de la
    pantalla (giro acotado a MAX_TURN_DEG por trazo) para no quedar atrapado en
    una esquina sin necesidad de un giro brusco.
    """
    w = RESOLUTION_WITHOUT_TASKBAR["x"]
    h = RESOLUTION_WITHOUT_TASKBAR["y"]
    cx, cy = w * 0.5, h * 0.5

    # Angulo base: el rumbo actual, o uno aleatorio si es el primer trazo.
    if state.heading is None:
        base = random.uniform(0.0, 2.0 * math.pi)
    else:
        base = state.heading

    # Pull hacia el centro proporcional a la cercania al borde.
    edge_x = min(state.x, w - state.x) / (w * 0.5)
    edge_y = min(state.y, h - state.y) / (h * 0.5)
    edge_factor = 1.0 - max(0.0, min(edge_x, edge_y))  # 0 centro, ~1 en borde

    max_turn = math.radians(MAX_TURN_DEG)
    desired_center = math.atan2(cy - state.y, cx - state.x)

    # Giro de exploracion aleatorio dentro del limite.
    explore_turn = random.uniform(-max_turn, max_turn)

    if edge_factor > 0.6:
        # Cerca del borde: girar hacia el centro, pero acotado a max_turn.
        turn = _ang_diff(base, desired_center)
        turn = max(-max_turn, min(max_turn, turn))
    else:
        turn = explore_turn

    angle = base + turn
    dist = random.uniform(STROKE_DIST_MIN, STROKE_DIST_MAX)
    tx = state.x + dist * math.cos(angle)
    ty = state.y + dist * math.sin(angle)

    # Acotar a la pantalla manteniendo el rumbo (el trazo se acorta si choca).
    tx = max(EDGE_MARGIN, min(w - EDGE_MARGIN, tx))
    ty = max(EDGE_MARGIN, min(h - EDGE_MARGIN, ty))
    return tx, ty


def _human_move_to(state, tx, ty, should_run):
    """Mueve el cursor hasta (tx,ty) con trayectoria de Bezier suave y
    temporizacion de minimo jerk, emitiendo SetCursorPos cada 12-18 ms.

    Esto garantiza:
      * Gozi: delta no nulo en practicamente cada muestreo de 64 ms.
      * LummaC2: angulos < 45 grados entre posiciones muestreadas a 50 ms,
        porque la curvatura es suave y el rumbo cambia gradualmente.
    """
    sx, sy = state.x, state.y
    dx, dy = tx - sx, ty - sy
    dist = math.hypot(dx, dy)
    if dist < 1.0:
        return

    # Duracion segun ley de Fitts simplificada + ruido gaussiano.
    dur = DUR_BASE_S + dist * DUR_PER_PX_S
    dur *= max(0.5, random.gauss(1.0, 0.12))
    dur = max(DUR_MIN_S, min(DUR_MAX_S, dur))

    # Punto de control perpendicular para una curva suave (no linea recta).
    ux, uy = dx / dist, dy / dist
    perp_x, perp_y = -uy, ux
    k = random.uniform(0.04, CURVE_K_MAX) * random.choice((-1.0, 1.0))
    ctrl_x = sx + dx * 0.5 + perp_x * (k * dist)
    ctrl_y = sy + dy * 0.5 + perp_y * (k * dist)

    elapsed = 0.0
    last_ix, last_iy = int(round(sx)), int(round(sy))
    while elapsed < dur and should_run():
        tau = elapsed / dur
        s = _min_jerk(tau)
        oms = 1.0 - s
        # Bezier cuadratica B(s) = (1-s)^2 P0 + 2(1-s)s C + s^2 P1
        x = oms * oms * sx + 2.0 * oms * s * ctrl_x + s * s * tx
        y = oms * oms * sy + 2.0 * oms * s * ctrl_y + s * s * ty
        ix, iy = int(round(x)), int(round(y))
        # Garantizar delta no nulo (relevante para Gozi).
        if ix == last_ix and iy == last_iy:
            if ux != 0 or uy != 0:
                ix += 1 if ux >= 0 else -1
        USER32.SetCursorPos(ix, iy)
        last_ix, last_iy = ix, iy
        dt = random.uniform(STEP_MIN_MS, STEP_MAX_MS) / 1000.0
        time.sleep(dt)
        elapsed += dt

    USER32.SetCursorPos(int(round(tx)), int(round(ty)))
    # Actualizar estado: el nuevo rumbo es la direccion de la cuerda del trazo.
    state.heading = math.atan2(ty - sy, tx - sx)
    state.x, state.y = tx, ty


def _human_pause():
    """Pausa breve y poco frecuente (40-180 ms). A diferencia del Sleep(1000)
    original, es lo bastante corta como para no romper la deteccion de
    movimiento continuo de Gozi ni el muestreo de 50 ms de LummaC2."""
    time.sleep(random.uniform(0.04, 0.18))


class HumanImproved(Auxiliary, Thread):
    """Modulo de interaccion humana mejorado (TFG).

    Se activa solo con la opcion human_improved=1. Genera movimiento de raton
    continuo, suave y estadisticamente conforme al modelo que asumen los
    mecanismos RTT de Gozi/Ursnif y LummaC2 v4.0.
    """

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.options = options
        # Solo se habilita si la interaccion humana esta activa en la config
        # global Y se ha pasado la flag human_improved.
        self.enabled = bool(getattr(self.config, "human_windows", True)) and bool(options.get("human_improved"))
        self.do_run = self.enabled

    def stop(self):
        self.do_run = False

    def _should_run(self):
        return self.do_run

    def run(self):
        if not self.enabled:
            return True
        if self.options.get("nohuman"):
            return True
        try:
            populate_clipboard()
            USER32.EnumWindows(EnumWindowsProc(get_window_list), 0)

            state = _MovementState()
            cycle = 0
            randoff = random.randint(0, 10)

            while self.do_run:
                # 1) Trazo de movimiento humano continuo.
                tx, ty = _pick_next_target(state)
                _human_move_to(state, tx, ty, self._should_run)

                # 2) Clic ocasional (15%), evitando ventanas de consola.
                if random.random() < 0.15 and not cursor_over_console_window():
                    click_mouse()

                # 3) Pausa breve y rara (4%).
                if random.random() < 0.04:
                    _human_pause()

                # 4) Interaccion periodica con botones/dialogos (barata).
                if cycle % 8 == 0:
                    USER32.EnumWindows(EnumWindowsProc(handle_window_interaction), 0)

                # 5) Cierre de ventanas de documento (maldocs) periodicamente.
                if cycle % 20 == 0:
                    USER32.EnumWindows(EnumWindowsProc(get_document_window), 0)

                # 6) Cambio ocasional de ventana en primer plano.
                if cycle % (15 + randoff) == 0:
                    other = INITIAL_HWNDS.copy()
                    with contextlib.suppress(Exception):
                        other.remove(USER32.GetForegroundWindow())
                    if other:
                        USER32.SetForegroundWindow(other[random.randint(0, len(other) - 1)])

                cycle += 1
        except Exception:
            log.exception(traceback.format_exc())
