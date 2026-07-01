#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------------------
# dialog_handler.py - Modulo auxiliar de interaccion con dialogos para CAPEv2
#
# TFG: Identificacion y simulacion de triggers de interaccion humana en
#      analisis dinamico de malware.
# Autor: Nicolas Fabra (Universidad de Zaragoza)
#
# OBJETIVO
# --------
# Se ocupa del canal RTT de "evento discreto": clics y confirmacion de
# dialogos. Complementa a human_improved.py (que solo mueve el cursor).
#
# POR QUE CLICS FISICOS Y NO BM_CLICK
# -----------------------------------
# El human.py original confirma dialogos con SendMessageW(BM_CLICK), que es un
# "clic logico": activa el boton pero NO mueve el raton fisico ni lo coloca
# sobre el. Pafish detecta esto y lo marca como bot, porque sus checks de clic
# y de "plausible dialog confirmation" comprueban el estado del boton FISICO
# del raton (GetAsyncKeyState(VK_LBUTTON)) y la posicion real del cursor.
#
# Por eso este modulo hace CLICS FISICOS REALES: localiza el boton en pantalla
# con GetWindowRect, mueve el cursor a su centro con SetCursorPos, y pulsa con
# mouse_event. Asi el clic es indistinguible del de un humano para Pafish.
#
# ACTIVACION
# ----------
# Se activa con la opcion de submit:  dialog_handler=1
# ---------------------------------------------------------------------------

import logging
import os
import random
import time
import traceback
from ctypes import WINFUNCTYPE, byref, c_bool, create_unicode_buffer, wintypes
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import (
    KERNEL32,
    USER32,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
)

log = logging.getLogger(__name__)

# Fichero marca: lo creo cuando voy a confirmar un dialogo para que
# human_improved se quede quieto y no me robe el cursor ni el foco.
HOLD_FLAG_PATH = os.path.join(os.environ.get("TEMP", "C:\\Windows\\Temp"), "cape_dialog_hold.flag")

def _hold_for(seconds):
    # Escribo en el fichero el instante hasta el que human_improved debe estar
    # quieto. Se reanuda solo al pasar ese instante (no hace falta borrar nada).
    try:
        with open(HOLD_FLAG_PATH, "w") as fh:
            fh.write(str(time.time() + seconds))
    except Exception:
        pass


EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
EnumChildProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

# Conjunto de handles de dialogos ya confirmados (por ventana, no por texto),
# dialogo en cada pasada del bucle (era la causa de que clicara sin parar).
CONFIRMED_BUTTONS = set()

# ---------------------------------------------------------------------------
# PARAMETROS DE TIMING HUMANO
# ---------------------------------------------------------------------------
# Cada cuantos segundos reales reviso si hay dialogos abiertos.
SCAN_EVERY_S = 0.2

# Antes de confirmar un dialogo espero un rato plausible (un humano lee antes
# de pulsar). Esto es lo que satisface "plausible dialog confirmation".
DIALOG_WAIT_MIN_S = 0.4
DIALOG_WAIT_MAX_S = 1.0

# Intervalo entre bajar y subir el boton del raton en un clic (variable, no fijo).
CLICK_HOLD_MIN_S = 0.05
CLICK_HOLD_MAX_S = 0.14

# Separacion humana entre los dos clics de un doble clic.
DOUBLE_CLICK_GAP_MIN_S = 0.06
DOUBLE_CLICK_GAP_MAX_S = 0.17

# Movimiento de aproximacion al boton antes de clicar.
APPROACH_STEPS = 10
APPROACH_STEP_MS = 12

# Textos de boton que SI confirmo.
CLICK_BUTTONS = (
    # Solo botones de CONFIRMACION, para no clicar en cualquier control. Esto
    # cubre los dialogos Si/No/Aceptar de Pafish y de LummaC2 2025.
    "yes", "ok", "accept", "agree", "aceptar", "si",
    "ja", "akzeptieren", "stimme zu", "zustimmen", "einverstanden",
)

# Textos de boton que NUNCA pulso.
DONT_CLICK_BUTTONS = (
    "cancel", "don't run", "do not accept the agreement", "abbrechen",
    "abbruch", "nicht ausfuehren", "stimme nicht zu",
)


# ===========================================================================
# FUNCIONES AUXILIARES
# ===========================================================================

def get_window_text(hwnd):
    # Saco el texto de una ventana o boton.
    length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    if length == 0:
        return ""
    text = create_unicode_buffer(length + 1)
    USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)
    return text.value.replace("&", "")


def cursor_over_console_window():
    # Compruebo si el cursor esta sobre una ventana de consola. No quiero clicar
    # ahi: un clic en una consola activa su modo de marcado y CONGELA su salida,
    # que es justo lo que impedia ver los checks de Pafish.
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    hwnd = USER32.WindowFromPoint(pt)
    if not hwnd or not USER32.IsWindowVisible(hwnd):
        return False
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    return "ConsoleWindowClass" in str(classname_ptr.value)


def get_button_center(hwnd):
    # Localizo el boton en pantalla con GetWindowRect y devuelvo su punto
    # central, que es donde voy a hacer el clic fisico.
    rect = wintypes.RECT()
    if not USER32.GetWindowRect(hwnd, byref(rect)):
        return None
    cx = (rect.left + rect.right) // 2
    cy = (rect.top + rect.bottom) // 2
    return (cx, cy)


def move_cursor_to(x, y):
    # Muevo el cursor hasta (x, y) en varios pasos cortos, en vez de un salto
    # seco, para que el desplazamiento parezca humano antes de clicar.
    cur = wintypes.POINT()
    USER32.GetCursorPos(byref(cur))
    sx, sy = cur.x, cur.y
    for i in range(1, APPROACH_STEPS + 1):
        nx = int(sx + (x - sx) * i / APPROACH_STEPS)
        ny = int(sy + (y - sy) * i / APPROACH_STEPS)
        USER32.SetCursorPos(nx, ny)
        time.sleep(APPROACH_STEP_MS / 1000.0)
    USER32.SetCursorPos(int(x), int(y))


def physical_click_at(x, y):
    # Clic fisico real: muevo el cursor al punto y pulso con mouse_event. A
    # diferencia de BM_CLICK, esto SI mueve el raton fisico y deja el estado del
    # boton que Pafish comprueba con GetAsyncKeyState.
    # Salto directo al boton (sin pasos): el dialogo solo vive 3s, no puedo
    # gastar tiempo en un movimiento lento.
    USER32.SetCursorPos(int(x), int(y))
    time.sleep(0.03)
    USER32.mouse_event(2, 0, 0, 0, None)            # Bajo el boton izquierdo
    time.sleep(0.04)
    USER32.mouse_event(4, 0, 0, 0, None)            # Subo el boton izquierdo
    # Dejo el cursor sobre el boton un momento para que Pafish procese el clic
    # con el cursor dentro del dialogo (check plausible), pero sin pasarme.
    time.sleep(0.3)


def physical_click_here():
    # Clic fisico en la posicion actual del cursor (genera la actividad de clic
    # suelto que satisface el check "mouse click activity"). NO clico si el
    # cursor esta sobre una consola, para no congelar su salida.
    if cursor_over_console_window():
        return
    USER32.mouse_event(2, 0, 0, 0, None)
    time.sleep(random.uniform(CLICK_HOLD_MIN_S, CLICK_HOLD_MAX_S))
    USER32.mouse_event(4, 0, 0, 0, None)


def physical_double_click():
    # Doble clic fisico con separacion humana (satisface "double click activity").
    physical_click_here()
    time.sleep(random.uniform(DOUBLE_CLICK_GAP_MIN_S, DOUBLE_CLICK_GAP_MAX_S))
    physical_click_here()


def is_button_class(classname):
    # Decido si la clase de la ventana corresponde a un boton.
    return "button" in classname


def inspect_control(hwnd, lparam):
    # Callback por cada control hijo de un dialogo: si es un boton con texto de
    # mi lista, lo confirmo con un CLIC FISICO sobre su posicion real.
    if not USER32.IsWindowVisible(hwnd) or not USER32.IsWindowEnabled(hwnd):
        return True
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    classname = str(classname_ptr.value).lower()
    if not is_button_class(classname):
        return True
    button_text = get_window_text(hwnd).lower()
    if button_text == "":
        return True
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]:
        return True
    if [t for t in CLICK_BUTTONS if t in button_text]:
        GA_ROOT = 2
        dialog_hwnd = USER32.GetAncestor(hwnd, GA_ROOT)
        # No repito el MISMO dialogo (mismo handle de ventana), pero SI atiendo
        # dialogos nuevos aunque su boton tenga el mismo texto. Pafish crea un
        # dialogo distinto para el check simple y para el plausible.
        if dialog_hwnd in CONFIRMED_BUTTONS:
            return True
        center = get_button_center(hwnd)
        if center is None:
            return True
        log.info('Dialog button "%s" found, confirming', button_text)
        # LO PRIMERO: pauso human_improved durante ~1.5s, tiempo de sobra para
        # toda la operacion. Se reanuda solo al pasar ese tiempo.
        _hold_for(1.5)
        # Traigo al frente la ventana del dialogo. Uso el truco de la tecla ALT
        # para desbloquear SetForegroundWindow dentro de la VM.
        if dialog_hwnd:
            USER32.keybd_event(0x12, 0, 0, 0)       # Pulso ALT
            USER32.keybd_event(0x12, 0, 2, 0)       # Suelto ALT
            USER32.SetForegroundWindow(dialog_hwnd)
            USER32.BringWindowToTop(dialog_hwnd)
            USER32.SetWindowPos(dialog_hwnd, -1, 0, 0, 0, 0, 0x0001 | 0x0002)  # HWND_TOPMOST
            KERNEL32.Sleep(30)
        physical_click_at(center[0], center[1])     # Clic fisico sobre el boton
        time.sleep(0.3)                             # Dejo que Pafish procese el clic
        CONFIRMED_BUTTONS.add(dialog_hwnd)          # Marco ESTE dialogo como confirmado
        return False
    return True


def handle_dialog(hwnd, lparam):
    # Callback por cada ventana de primer nivel: recorro sus controles hijos
    # buscando botones que confirmar.
    if not USER32.IsWindowVisible(hwnd):
        return True
    USER32.EnumChildWindows(hwnd, EnumChildProc(inspect_control), 0)
    return True


class DialogHandler(Auxiliary, Thread):
    # Modulo de interaccion con dialogos mediante clics fisicos reales.

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.options = options
        self.enabled = bool(getattr(self.config, "human_windows", True)) and bool(options.get("dialog_handler"))
        self.do_run = self.enabled

    def stop(self):
        self.do_run = False

    def run(self):
        if not self.enabled:
            return True
        if self.options.get("nohuman"):
            return True
        try:
            time.sleep(random.uniform(1.0, 2.0))   # Pequena espera inicial

            # Bucle principal. En cada vuelta hago dos cosas:
            #  1) genero actividad de clic (suelto y, de vez en cuando, doble),
            #     de forma repetida para caer dentro de la ventana de 3 s en que
            #     Pafish escucha sus checks de clic y doble clic;
            #  2) reviso si hay dialogos abiertos y los confirmo.
            while self.do_run:
                # Solo me encargo de detectar y confirmar dialogos. Los clics de
                # actividad (simple y doble) los hace human_improved, que es quien
                # controla el movimiento del cursor, para no pisarnos.
                USER32.EnumWindows(EnumWindowsProc(handle_dialog), 0)
                time.sleep(SCAN_EVERY_S)
        except Exception:
            log.exception(traceback.format_exc())