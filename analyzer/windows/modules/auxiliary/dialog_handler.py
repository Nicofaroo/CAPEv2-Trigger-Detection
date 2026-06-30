#!/usr/bin/env python

import logging
import random
import time
import traceback
from ctypes import WINFUNCTYPE, byref, c_bool, create_unicode_buffer, wintypes
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.defines import (
    BM_CLICK,
    BM_GETCHECK,
    BM_SETCHECK,
    BST_CHECKED,
    KERNEL32,
    USER32,
    WM_GETTEXT,
    WM_GETTEXTLENGTH,
)

# Creo mi logger para dejar mensajes en el log de CAPE.
log = logging.getLogger(__name__)

# Defino los tipos de las funciones callback para recorrer ventanas y sus hijas.
EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
EnumChildProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

# ---------------------------------------------------------------------------
# PARAMETROS DE TIMING HUMANO
# ---------------------------------------------------------------------------
# Cada cuantos segundos (de reloj real, no ciclos) reviso si hay dialogos.
SCAN_EVERY_S = 1.5

# Antes de confirmar un dialogo, espero un rato "humano": ni instantaneo (eso
# delata al bot en el check plausible dialog confirmation) ni demasiado tarde.
DIALOG_WAIT_MIN_S = 0.8
DIALOG_WAIT_MAX_S = 2.5

# Intervalo entre pulsar y soltar el boton en un clic. Es un RANGO, no un valor
# fijo: la regularidad de un Sleep fijo es justo lo que Pafish marca como bot.
CLICK_HOLD_MIN_S = 0.04
CLICK_HOLD_MAX_S = 0.13

# Separacion entre los dos clics de un doble clic (rapida pero humana).
DOUBLE_CLICK_GAP_MIN_S = 0.06
DOUBLE_CLICK_GAP_MAX_S = 0.18

# Textos de boton que SI quiero pulsar (heredados del human.py original).
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
    "\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c",
)

# Textos de boton que NUNCA quiero pulsar (cancelar, no ejecutar...).
DONT_CLICK_BUTTONS = (
    "check online for a solution",
    "don't ask me again for remote connections from this publisher",
    "don't run", "do not ask again until the next update is available",
    "cancel", "do not accept the agreement",
    "i would like to help make reader even better", "restart now",
    "abbrechen", "online nach losung suchen", "abbruch", "nicht ausfuehren",
    "hilfe", "stimme nicht zu",
    "\u043f\u0440\u0438o\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c", "\u043e\u0442\u043c\u0435\u043d\u0430",
)

# Nombres de clase de los dialogos de Microsoft Office (se tratan con Enter).
OFFICE_WINDOW_CLASSES = ("nuidialog", "bosa_sdm_msword")


# ===========================================================================
# FUNCIONES AUXILIARES
# ===========================================================================

def get_window_text(hwnd):
    # Saco el texto (titulo o etiqueta) de una ventana o boton.
    length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    if length == 0:
        return ""
    text = create_unicode_buffer(length + 1)
    USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)
    return text.value.replace("&", "")


def is_button_checked(hwnd):
    # Pregunto si un checkbox o radio esta marcado.
    return bool(USER32.SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED)


def human_click(hwnd):
    # Pulso un boton concreto con un tiempo de espera variable (no fijo), para
    # que el patron temporal no sea el de un bot. Uso BM_CLICK (por mensaje),
    # asi no dependo de donde este el cursor fisico.
    USER32.SetForegroundWindow(hwnd)                    # Traigo la ventana al frente
    time.sleep(random.uniform(CLICK_HOLD_MIN_S, CLICK_HOLD_MAX_S))  # Espera variable, no los 50 ms fijos del original
    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)           # Pulso el boton


def human_physical_click():
    # Hago un clic fisico (con mouse_event) en la posicion actual del cursor,
    # con un intervalo variable entre bajar y subir el boton. Esto es lo que
    # satisface el check "mouse click activity" de Pafish, que mira esa cadencia.
    USER32.mouse_event(2, 0, 0, 0, None)                # Bajo el boton izquierdo
    time.sleep(random.uniform(CLICK_HOLD_MIN_S, CLICK_HOLD_MAX_S))  # Espera variable
    USER32.mouse_event(4, 0, 0, 0, None)                # Subo el boton izquierdo


def human_double_click():
    # Hago un doble clic con una separacion humana entre los dos clics. Esto
    # satisface el check "mouse double click activity" de Pafish.
    human_physical_click()                              # Primer clic
    time.sleep(random.uniform(DOUBLE_CLICK_GAP_MIN_S, DOUBLE_CLICK_GAP_MAX_S))  # Separacion humana
    human_physical_click()                              # Segundo clic


def is_button(classname):
    # Decido si un control cuenta como boton.
    return bool("button" in classname or classname in OFFICE_WINDOW_CLASSES)


def confirm_dialog_button(hwnd, classname):
    # Confirmo un boton de dialogo, pero esperando antes un tiempo plausible.
    # Esa espera es la que hace pasar el check "plausible dialog confirmation":
    # un humano tarda un poco en leer y pulsar, no responde al instante.
    button_text = get_window_text(hwnd)
    if button_text == "" or not USER32.IsWindowEnabled(hwnd):
        return True
    # Dialogo de Office: lo confirmo con Enter, tras una espera humana.
    if "Microsoft" in button_text and classname in OFFICE_WINDOW_CLASSES:
        time.sleep(random.uniform(DIALOG_WAIT_MIN_S, DIALOG_WAIT_MAX_S))  # Espera plausible
        USER32.SetForegroundWindow(hwnd)
        USER32.keybd_event(0x0D, 0x1C, 0, 0)            # Pulso Enter
        USER32.keybd_event(0x0D, 0x1C, 2, 0)            # Suelto Enter
        return False
    button_text = button_text.lower()
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]:
        return True                                     # No toco botones de la lista negra
    if [t for t in CLICK_BUTTONS if t in button_text]:
        log.info('Dialog button found "%s", confirming after human delay', button_text)
        time.sleep(random.uniform(DIALOG_WAIT_MIN_S, DIALOG_WAIT_MAX_S))  # Espera plausible antes de confirmar
        human_click(hwnd)                               # Lo pulso con timing humano
        return False
    return True


def confirm_checkbox(hwnd):
    # Marco un checkbox/radio si su texto esta en la lista de "pulsar".
    if is_button_checked(hwnd):
        return True
    button_text = get_window_text(hwnd).lower()
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]:
        return True
    if [t for t in CLICK_BUTTONS if t in button_text]:
        human_click(hwnd)
        if not is_button_checked(hwnd):
            USER32.SendMessageW(hwnd, BM_SETCHECK, BST_CHECKED, 0)
        return False
    return True


def inspect_control(hwnd, lparam):
    # Callback por cada control: decido si es checkbox/radio o boton y actuo.
    if not USER32.IsWindowVisible(hwnd):
        return True
    classname_ptr = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, classname_ptr, 128)
    classname = str(classname_ptr.value).lower()
    if "checkbox" in classname or "radiobutton" in classname:
        return confirm_checkbox(hwnd)
    elif is_button(classname):
        return confirm_dialog_button(hwnd, classname)
    return True


def handle_dialog(hwnd, lparam):
    # Callback por cada ventana de primer nivel: la inspecciono y luego recorro
    # sus controles hijos (los botones suelen ser hijos del dialogo).
    inspect_control(hwnd, lparam)
    USER32.EnumChildWindows(hwnd, EnumChildProc(inspect_control), 0)
    return True


class DialogHandler(Auxiliary, Thread):
    # Modulo que se ocupa solo de clics y dialogos, con timing humano.
    # Corre en su propio hilo, en paralelo al malware y, si esta activo, a
    # human_improved (que se ocupa del movimiento).

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.options = options
        # Me activo solo si se ha pasado la opcion dialog_handler=1.
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
            # Al arrancar, genero algo de actividad de clic con timing humano,
            # para satisfacer los checks de click simple y doble de Pafish.
            time.sleep(random.uniform(1.0, 2.0))   # Pequena espera inicial (parecer humano, no instantaneo)
            human_physical_click()                 # Un clic suelto con cadencia variable
            time.sleep(random.uniform(0.3, 0.8))
            human_double_click()                   # Un doble clic con separacion humana

            # Bucle principal: cada cierto tiempo REAL, reviso si hay dialogos
            # abiertos y los confirmo con espera plausible.
            while self.do_run:
                USER32.EnumWindows(EnumWindowsProc(handle_dialog), 0)
                time.sleep(SCAN_EVERY_S)
        except Exception:
            log.exception(traceback.format_exc())