#!/usr/bin/env python
# -*- coding: utf-8 -*-

import contextlib
import logging # Importo logging para poder escribir mensajes en el log de CAPE
import math # Importo math para usar senos, cosenos y angulos para mover el cursor
import random # Importo random para elejir destinos duraicionese y probabilidades al azar
import time # Importo time para poder hacer pausas y medir duraciones
import traceback # Importo traceback para poder volcar el error completo si algo falla dentro del hilo
from ctypes import WINFUNCTYPE, byref, c_bool, c_size_t, create_unicode_buffer, memmove, sizeof, wintypes
from threading import Thread # Importo Thread para poder crer un hilo que se ejecute en paralelocon el malware

from lib.common.abstracts import Auxiliary # Me traigo la clase base de la que heredan los modulos auxiliares de CAPE
from lib.common.defines import (
    BM_CLICK, # El codigo de mensaje para hacer click en un boton
    BM_GETCHECK, # El codigo de mensaje para saber si un boton esta checkeado
    BM_SETCHECK, # El codigo de mensaje para checkear un boton
    BST_CHECKED, # El valor que indica que un boton esta checkeado
    GMEM_MOVEABLE, # El valor que indica que la memoria es movible
    KERNEL32, # El handle a la libreria KERNEL32
    USER32, # El handle a la libreria USER32
    WM_CLOSE, # El codigo de mensaje para cerrar una ventana
    WM_GETTEXT, # El codigo de mensaje para obtener el texto de una ventana
    WM_GETTEXTLENGTH, # El codigo de mensaje para obtener la longitud del texto de una ventana
)

# Creo mi logger. Le paso el nombre del fichero para que mis mensajes salgan etiquetados en el log de CAPE
log = logging.getLogger(__name__)

# Defino los tipos de funciones que voy a usar para enumerar ventanas y controles
EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
EnumChildProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

# Guardo los numeros que Windows usa para identificar cada medida de pantalla
SM_CXSCREEN = 0 # Ancho total de la pantalla
SM_CYSCREEN = 1 # Alto total de la pantalla
SM_CXFULLSCREEN = 16 # Ancho de la pantalla sin la barra de tareas
SM_CYFULLSCREEN = 17 # Alto de la pantalla sin la barra de tareas

# Obtengo la resolucion de pantalla
RESOLUTION = {"x": USER32.GetSystemMetrics(SM_CXSCREEN), "y": USER32.GetSystemMetrics(SM_CYSCREEN)}

# Obtengo la resolucion de pantalla sin la barra de tareas
RESOLUTION_WITHOUT_TASKBAR = {"x": USER32.GetSystemMetrics(SM_CXFULLSCREEN), "y": USER32.GetSystemMetrics(SM_CYFULLSCREEN)}

INITIAL_HWNDS = [] # Preparo una lista vacia para guardar las ventanas qeu esten abiertas

CF_UNICODETEXT = 0x000D # Me guardo el valor que Windows usa para identificar el tipo de dato de texto unicode en el portapapeles


# ----------------------------------- Parametros de movimiento del cursor -----------------------------------

# Fijo cada cuanto tiempo muevo el cursor. Entre 12 y 18 milisegudos por paso
STEP_MIN_MS = 12
STEP_MAX_MS = 18

# Decido cuando puedo girar el cursor. 18 grados por paso
MAX_TURN_DEG = 18.0

# Decido cuanto se curva cada trazo. 7% de la distancia del trazo
CURVE_K_MAX = 0.07

# Decido la distancia minima y maxima de cada trazo. Entre 80 y 400 pixeles
STROKE_DIST_MIN = 80
STROKE_DIST_MAX = 400

# Calculo la duracion de cada trazo. Base de 0.28 segundos, mas 1 segundo por cada 900 pixeles, con un minimo de 0.28 y un maximo de 1.20 segundos
DUR_BASE_S = 0.28
DUR_PER_PX_S = 1.0 / 900.0
DUR_MIN_S = 0.28
DUR_MAX_S = 1.20

# Dejo un margen de 12 pixeles para que el cursor no se acerque demasiado a los bordes de la pantalla
EDGE_MARGIN = 12
# Dejo un margen de 1/4 del ancho de la pantalla para evitar hacer clic encima de iconos de escritorio
LEFT_ICON_MARGIN = RESOLUTION_WITHOUT_TASKBAR["x"] // 4

# Probabilidad de hacer un clic suelto en cada ciclo. Alta para que algun clic
# caiga dentro de la ventana de 3 s en que Pafish escucha su check de clic.
CLICK_PROB = 0.35

# Probabilidad de hacer un doble clic en cada ciclo (Pafish exige dos clics en
# menos de 500 ms).
DOUBLE_CLICK_PROB = 0.20

# Separacion entre los dos clics del doble clic (debe ser menor de 500 ms).
DOUBLE_CLICK_GAP_S = 0.12

# ------------------------------------ Parametros de interaccion con ventanas -----------------------------------

# Cada cuantos ciclos de movimiento del cursor interactuo con las ventanes. 40 ciclos
WINDOW_INTERACT_EVERY = 40

# Cada cuantos ciclos de movimiento del cursor cierro ventanas de documentos. 60 ciclos
DOC_CLOSE_EVERY = 60

# Decido si quiero cambiar de ventana activa cada 15 ciclos. False para no cambiar de ventana activa
ENABLE_FOREGROUND_SWITCH = False

# Lista con textos de botones que si que quiero pulsar
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

# Lista con textos de botones que no quiero pulsar
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

# Me guardo los nombres de las clases de ventanas de Microsoft Office para mas adelante
OFFICE_WINDOW_CLASSES = ("nuidialog", "bosa_sdm_msword")

# Para cada funcion de windows que voy a usar le indico que tipo de argumentos recibe y que tipo devuelve
# Esto lo hago ya que ctypes no sabe que tipo de datos devuelve cada funcion y por defecto asume que devuelve un int
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

# ------------------------------------ Funciones auxiliares de interaccion -----------------------------------

# Funcion para obtener la posicion actual del cursor
def get_cursor_position():
    pt = wintypes.POINT() # Creo un objeto POINT para guardar la posicion del cursor
    USER32.GetCursorPos(byref(pt)) # Llamo a la funcion GetCursorPos de USER32 para obtener la posicion del cursor y guardarla en el objeto POINT
    return (pt.x, pt.y) # Devuelvo la posicion del cursor como una tupla (x, y)

# Funcion para saber si el cursor esta encima de una ventana de consola
def cursor_over_console_window():
    pt = wintypes.POINT() # Creo un objeto POINT para guardar la posicion del cursor
    USER32.GetCursorPos(byref(pt)) # Llamo a la funcion GetCursorPos de USER32 para obtener la posicion del cursor y guardarla en el objeto POINT
    hwnd = USER32.WindowFromPoint(pt) # Llamo a la funcion WindowFromPoint de USER32 para saber qeu ventana esta debajo del cursor
    if not hwnd or not USER32.IsWindowVisible(hwnd): # Si no hay ventana debajo del cursor o la ventana no es visible, devuelvo False
        return False
    classname_ptr = create_unicode_buffer(128) # Creo un buffer de 128 caracteres para guardar el nombre de la clase de la ventana
    USER32.GetClassNameW(hwnd, classname_ptr, 128) # Llamo a la funcion GetClassNameW de USER32 para obtener el nombre de la clase de la ventana y guardarlo en el buffer
    return "ConsoleWindowClass" in str(classname_ptr.value) # Devuelvo True si el nombre de la clase de la ventana contiene "ConsoleWindowClass"

# Funcion para obtener el texto de una ventana
def get_window_text(hwnd):
    length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0) # Llamo a la funcion SendMessageW de USER32 para obtener la longitud del texto de la ventana
    if length == 0: # Si la longitud del texto es 0, devuelvo una cadena vacia
        return ""
    text = create_unicode_buffer(length + 1) # Creo un buffer de longitud + 1 para guardar el texto de la ventana
    USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text) # Llamo a la funcion SendMessageW de USER32 para obtener el texto de la ventana y guardarlo en el buffer
    return text.value.replace("&", "") # Devuelvo el texto de la ventana como una cadena, eliminando los caracteres "&" que se usan para indicar teclas de acceso rapido

# Funcion para saber si un boton esta checkeado
def is_button_checked(hwnd):
    return bool(USER32.SendMessageW(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED) # Llamo a la funcion SendMessageW de USER32 para obtener el estado del boton y devuelvo True si esta checkeado, False si no lo esta

# Funcion para enviar un click a un boton
def send_click(hwnd):
    USER32.SetForegroundWindow(hwnd) # Primero traigo la ventana del boton al frente
    KERNEL32.Sleep(20) # Espero 20 milisegundos para que la ventana se traiga al frente
    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0) # Llamo a la funcion SendMessageW de USER32 para enviar el mensaje BM_CLICK al boton, que hace que se haga click en el boton

# Funcion para hacer click en un boton
def click_button(hwnd, classname):
    button_text = get_window_text(hwnd) # Obtengo el texto del boton
    if button_text == "" or not USER32.IsWindowEnabled(hwnd): # Si el boton no tiene texto o no esta habilitado, devuelvo True para que no se haga click en el boton
        return True
    if "Microsoft" in button_text and classname in OFFICE_WINDOW_CLASSES: # Si es un dialogo de Office, pulso Enter para confirmarlo
        USER32.SetForegroundWindow(hwnd) # Traigo la ventana al frente
        USER32.keybd_event(0x0D, 0x1C, 0, 0) # Simulo pulsar Enter
        USER32.keybd_event(0x0D, 0x1C, 2, 0) # Simulo soltar Enter
        return False
    button_text = button_text.lower() # Paso el texto a minusculas para evitar problemas
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]: # Si el texto del boton contiene algun texto de la lista DONT_CLICK_BUTTONS, devuelvo True para que no se haga click en el boton
        return True
    if [t for t in CLICK_BUTTONS if t in button_text]: # Si el texto del boton contiene algun texto de la lista CLICK_BUTTONS, hago click en el boton
        log.info('Found button "%s", clicking it', button_text) # Escribo en el log que he encontrado un boton y que voy a hacer click en el
        send_click(hwnd) # Llamo a la funcion send_click para hacer click en el boton
        return False
    return True

# Funcion para checkear un boton
def check_button(hwnd):
    if is_button_checked(hwnd): # Si el boton ya esta checkeado, devuelvo True para que no se haga nada
        return True
    button_text = get_window_text(hwnd).lower() # Obtengo el texto del boton y lo paso a minusculas para evitar problemas
    if [t for t in DONT_CLICK_BUTTONS if t in button_text]: # Si el texto del boton contiene algun texto de la lista DONT_CLICK_BUTTONS, devuelvo True para que no se haga click en el boton
        return True
    if [t for t in CLICK_BUTTONS if t in button_text]: # Si el texto del boton contiene algun texto de la lista CLICK_BUTTONS, hago click en el boton
        send_click(hwnd) # Llamo a la funcion send_click para hacer click en el boton
        if not is_button_checked(hwnd): # Si el boton no esta checkeado despues de hacer click, lo checkeo manualmente para asegurarme de que se ha checkeado
            USER32.SendMessageW(hwnd, BM_SETCHECK, BST_CHECKED, 0) # Llamo a la funcion SendMessageW de USER32 para enviar el mensaje BM_SETCHECK al boton, que hace que se checkee el boton
        return False
    return True

# Funcion para saber si una clase de ventana es un boton
def is_button(classname):
    return bool("button" in classname or classname in OFFICE_WINDOW_CLASSES)

# Funcion para interactuar con una ventana
def interact_with_window(hwnd, lparam):
    if not USER32.IsWindowVisible(hwnd): # Si la ventana no es visible, devuelvo True para que no se haga nada
        return True
    classname_ptr = create_unicode_buffer(128) # Creo un buffer de 128 caracteres para guardar el nombre de la clase de la ventana
    USER32.GetClassNameW(hwnd, classname_ptr, 128) # Llamo a la funcion GetClassNameW de USER32 para obtener el nombre de la clase de la ventana y guardarlo en el buffer
    classname = str(classname_ptr.value).lower() # Paso el nombre de la clase a minusculas para evitar problemas
    if "checkbox" in classname or "radiobutton" in classname: # Si la clase de la ventana es un checkbox o un radiobutton, llamo a la funcion check_button para checkearlo si es necesario
        return check_button(hwnd)
    elif is_button(classname): # Si la clase de la ventana es un boton, llamo a la funcion click_button para hacer click en el si es necesario
        return click_button(hwnd, classname)
    return True

# Funcion que lanzo sobre cada ventana
def handle_window_interaction(hwnd, lparam):
    interact_with_window(hwnd, lparam) # Llamo a la funcion interact_with_window para interactuar con la ventana
    USER32.EnumChildWindows(hwnd, EnumChildProc(interact_with_window), 0) # Recorro todas sus ventanas hijas
    return True

# Funcion que uso al arrancar para apuntar todas las ventanas que ya estan abiertas
def get_window_list(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd): # Si la ventana es visible
        INITIAL_HWNDS.append(hwnd)  # Guardo su handle en mi lista inicial
    return True

# Funcion que uso para cerrar ventanas de documentos
def get_document_window(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd): # Si la ventana es visible
        text = create_unicode_buffer(1024) # Creo un buffer de 1024 caracteres para guardar el texto de la ventana
        USER32.GetWindowTextW(hwnd, text, 1024) # Llamo a la funcion GetWindowTextW de USER32 para obtener el texto de la ventana y guardarlo en el buffer
        if any(v in text.value for v in ("- Microsoft", "- Word", "- Excel",
                                         "- PowerPoint", "- Adobe", "- Acrobat",
                                         "- Reader", "- PDF")): # Si el texto de la ventana contiene alguno de los textos que indican que es una ventana de documento
            log.info("Closing document window") # Escribo en el log que voy a cerrar la ventana de documento
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None) # Llamo a la funcion SendNotifyMessageW de USER32 para enviar el mensaje WM_CLOSE a la ventana, que hace que se cierre
    return True

# Funcion para rellenar el portapapeles con texto aleatorio
def populate_clipboard():
    randchars = list("   aaaabcddeeeeeefghhhiiillmnnnooooprrrsssttttuwy") # Creo una lista de caracteres aleatorios para rellenar el portapapeles
    cliplen = random.randint(10, 1000) # Decido la longitud del texto aleatorio que voy a poner en el portapapeles, entre 10 y 1000 caracteres
    clipstr = "".join(randchars[random.randint(0, len(randchars) - 1)] for _ in range(cliplen)) # Construyo el texto sacando caracteres aleatorios de la lista randchars
    cliprawstr = create_unicode_buffer(clipstr) # Creo un buffer de caracteres unicode con el texto aleatorio
    if not USER32.OpenClipboard(None): # Intento abrir el portapapeles para poder escribir en el
        return
    try:
        USER32.EmptyClipboard() # Borro el contenido del portapapeles
        buf = KERNEL32.GlobalAlloc(GMEM_MOVEABLE, sizeof(cliprawstr)) # Reservo memoria global para el texto aleatorio
        if not buf: # Si no he podido reservar memoria, salgo de la funcion
            return
        lockbuf = KERNEL32.GlobalLock(buf) # Bloqueo la memoria reservada para poder escribir en ella
        if not lockbuf: # Si no he podido bloquear la memoria, salgo de la funcion
            return
        memmove(lockbuf, cliprawstr, sizeof(cliprawstr)) # Copio el texto aleatorio al buffer de memoria bloqueada
        KERNEL32.GlobalUnlock(buf) # Desbloqueo la memoria reservada
        USER32.SetClipboardData(CF_UNICODETEXT, buf) # Pongo el buffer de memoria en el portapapeles como texto unicode
    finally:
        USER32.CloseClipboard() # Cierro el portapapeles para que otros programas puedan usarlo


# Funcion para hacer un clic simple con el raton
def click_mouse():
    USER32.mouse_event(2, 0, 0, 0, None) # Bajo el boton izquierdo del raton
    KERNEL32.Sleep(50) # Espero 50 ms
    USER32.mouse_event(4, 0, 0, 0, None) # Subo el boton izquierdo del raton

# Funcion para hacer un doble clic con el raton
def double_click_mouse():
    # Dos clics seguidos separados por menos de 500 ms, que es lo que Pafish
    # comprueba en su check de doble clic.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(40)
    USER32.mouse_event(4, 0, 0, 0, None)
    time.sleep(DOUBLE_CLICK_GAP_S)
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(40)
    USER32.mouse_event(4, 0, 0, 0, None)


# ------------------------------------ Confirmacion de dialogos -----------------------------------

# Conjunto de handles de dialogos ya confirmados (por ventana, no por texto),
# para no repetir el mismo dialogo pero si atender los nuevos.
CONFIRMED_DIALOGS = set()

# Textos de boton de confirmacion que quiero pulsar en un dialogo.
DIALOG_CONFIRM_TEXTS = ("yes", "ok", "accept", "agree", "aceptar", "si", "s\u00ed", "ja", "aceptar", "acepto")

def _get_button_center(hwnd):
    # Calculo el centro del boton en pantalla, que es donde hare el clic fisico.
    rect = wintypes.RECT()
    if not USER32.GetWindowRect(hwnd, byref(rect)):
        return None
    return ((rect.left + rect.right) // 2, (rect.top + rect.bottom) // 2)

def _confirm_dialog_button(hwnd, lparam):
    # Callback por cada control hijo: si es un boton de confirmacion de un
    # dialogo nuevo, lo traigo al frente y lo pulso con un clic fisico. Como
    # esto corre en el MISMO hilo que el movimiento, nada me pisa el cursor.
    if not USER32.IsWindowVisible(hwnd) or not USER32.IsWindowEnabled(hwnd):
        return True
    cls = create_unicode_buffer(128)
    USER32.GetClassNameW(hwnd, cls, 128)
    if "button" not in str(cls.value).lower():
        return True
    text = get_window_text(hwnd).lower()
    if text == "" or text not in DIALOG_CONFIRM_TEXTS:
        return True
    GA_ROOT = 2
    dialog_hwnd = USER32.GetAncestor(hwnd, GA_ROOT)
    if dialog_hwnd in CONFIRMED_DIALOGS:
        return True
    center = _get_button_center(hwnd)
    if center is None:
        return True
    log.info('Dialog button "%s" found, confirming', text)
    # Traigo el dialogo al frente (truco ALT para el foreground lock de la VM).
    if dialog_hwnd:
        USER32.keybd_event(0x12, 0, 0, 0)
        USER32.keybd_event(0x12, 0, 2, 0)
        USER32.SetForegroundWindow(dialog_hwnd)
        USER32.BringWindowToTop(dialog_hwnd)
        USER32.SetWindowPos(dialog_hwnd, -1, 0, 0, 0, 0, 0x0001 | 0x0002)
        KERNEL32.Sleep(30)
    # Clic fisico directo sobre el boton (salto directo, sin pasos lentos).
    USER32.SetCursorPos(int(center[0]), int(center[1]))
    KERNEL32.Sleep(30)
    # DIAG: compruebo donde quedo el cursor respecto al boton objetivo
    _cur = wintypes.POINT()
    USER32.GetCursorPos(byref(_cur))
    _fg = USER32.GetForegroundWindow()
    log.info("DIAG dialogo: objetivo=(%d,%d) cursor=(%d,%d) foreground=%s dialog_hwnd=%s",
             center[0], center[1], _cur.x, _cur.y, _fg, dialog_hwnd)
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(40)
    USER32.mouse_event(4, 0, 0, 0, None)
    KERNEL32.Sleep(300)   # Dejo el cursor sobre el boton
    # DIAG: ¿sigue existiendo el dialogo tras el clic? Si se cerro, es que funciono
    _still = USER32.IsWindowVisible(dialog_hwnd) if dialog_hwnd else 0
    log.info("DIAG tras clic: dialogo sigue visible=%s", _still)
    CONFIRMED_DIALOGS.add(dialog_hwnd)
    return False

def _scan_and_confirm_dialogs(hwnd, lparam):
    # Recorro las ventanas hijas de cada ventana de primer nivel buscando
    # botones de confirmacion.
    if not USER32.IsWindowVisible(hwnd):
        return True
    USER32.EnumChildWindows(hwnd, EnumChildProc(_confirm_dialog_button), 0)
    return True


# ------------------------------------ Motor del movimiento -----------------------------------

# Calculo cuanto del trazo llevo recorrido segun el modelo de movimiento de minima aceleracion (min jerk)
def _min_jerk(tau):
    if tau <= 0.0: # Si todavia no ha empezado
        return 0.0 # no he avanzado nada
    if tau >= 1.0: # si ya he terminado
        return 1.0 # he avanzado todo
    return 10.0 * tau ** 3 - 15.0 * tau ** 4 + 6.0 * tau ** 5 # Calculo el avance segun la formula de minima aceleracion

# Calculo el giro mas corto para pasar del angulo a al angulo b
def _ang_diff(a, b):
    d = (b - a) % (2.0 * math.pi) # Calculo la diferencia y la dejo en el rango 0..360
    if d > math.pi: # Si la diferencia es mayor de 180 grados, giro en sentido contrario
        d -= 2.0 * math.pi
    return d

# Clase para guardar el estado del movimiento del cursor
class _MovementState:

    def __init__(self):
        x, y = get_cursor_position() # Obtengo la posicion actual del cursor
        self.x = float(x) # Me guardo su x
        self.y = float(y) # Me guardo su y
        self.heading = None # Me guardo la direccion en la que se mueve el cursor, que al principio es None

# Elijo donde mover el cursor en el siguiente trazo, girando como mucho MAX_TURN_DEG grados y evitando acercarme a los iconos
def _pick_next_target(state):
    w = RESOLUTION_WITHOUT_TASKBAR["x"] # Me guardo el ancho util de la pantalla
    h = RESOLUTION_WITHOUT_TASKBAR["y"] # Me guardo el alto util de la pantalla
    cx = LEFT_ICON_MARGIN + (w - LEFT_ICON_MARGIN) * 0.5 # Calculo el centro al que tirar si me acerco a un borde
    cy = h * 0.5 # El centro en vertival es la mitad del alto util de la pantalla

    if state.heading is None: # Si es el primer trazo
        base = random.uniform(0.0, 2.0 * math.pi) # Elijo una direccion de partida al azar
    else:
        base = state.heading # Sino, sigo la direccion en la que se movia el cursor

    #Calculo lo cerca que estoy de los bordes
    edge_x = min(state.x, w - state.x) / (w * 0.5)
    edge_y = min(state.y, h - state.y) / (h * 0.5)
    edge_factor = 1.0 - max(0.0, min(edge_x, edge_y)) # Convierto eso en un factor de borde. 0 si estoy en el centro, 1 si estoy en un borde

    max_turn = math.radians(MAX_TURN_DEG) # Convierto el maximo giro a radianes
    desired_center = math.atan2(cy - state.y, cx - state.x) # Calculo el angulo hacia el centro de la pantalla
    explore_turn = random.uniform(-max_turn, max_turn) # Elijo un giro al azar entre -max_turn y max_turn

    if edge_factor > 0.6: # Si estoy cerca de un borde, giro hacia el centro
        turn = _ang_diff(base, desired_center) # Calculo el giro necesario para ir hacia el centro
        turn = max(-max_turn, min(max_turn, turn)) # Limito el giro al maximo permitido
    else: # Si estoy en el centro, giro al azar
        turn = explore_turn

    angle = base + turn # Calculo el angulo final sumando el giro al angulo base
    dist = random.uniform(STROKE_DIST_MIN, STROKE_DIST_MAX) # Elijo una distancia al azar entre STROKE_DIST_MIN y STROKE_DIST_MAX
    tx = state.x + dist * math.cos(angle) # Calculo la nueva posicion x sumando la distancia en la direccion del angulo. x
    ty = state.y + dist * math.sin(angle) # Calculo la nueva posicion y sumando la distancia en la direccion del angulo. y

    tx = max(LEFT_ICON_MARGIN, min(w - EDGE_MARGIN, tx)) # Limito la nueva posicion x para que no se acerque demasiado a los bordes de la pantalla y a los iconos
    ty = max(EDGE_MARGIN, min(h - EDGE_MARGIN, ty)) # Limito la nueva posicion y para que no se acerque demasiado a los bordes de la pantalla
    return tx, ty

# Funcion que mueve el cursor de forma humana desde la posicion actual hasta la posicion (tx, ty) en un tiempo dur, siguiendo una curva de minima aceleracion y con una curva aleatoria
def _human_move_to(state, tx, ty, should_run):
    sx, sy = state.x, state.y # Me guardo la posicion actual del cursor
    dx, dy = tx - sx, ty - sy # Calculo la distancia a recorrer en x y en y
    dist = math.hypot(dx, dy) # Calculo la distancia total a recorrer
    if dist < 1.0: # Si la distancia es menor a 1 pixel, no hago nada
        return

    # Calculo la duracion del trazo en segundos, sumando un factor aleatorio para que no sea siempre igual
    dur = DUR_BASE_S + dist * DUR_PER_PX_S
    dur *= max(0.5, random.gauss(1.0, 0.12))
    dur = max(DUR_MIN_S, min(DUR_MAX_S, dur))

    ux, uy = dx / dist, dy / dist # Calculo el vector unitario de la direccion del trazo
    perp_x, perp_y = -uy, ux # Calculo el vector perpendicular a la direccion del trazo
    k = random.uniform(0.04, CURVE_K_MAX) * random.choice((-1.0, 1.0)) # Elijo un factor de curvatura aleatorio entre -CURVE_K_MAX y CURVE_K_MAX
    ctrl_x = sx + dx * 0.5 + perp_x * (k * dist) # Calculo el punto de control de la curva en x, que es el punto medio del trazo mas un desplazamiento perpendicular proporcional a la distancia
    ctrl_y = sy + dy * 0.5 + perp_y * (k * dist) # Calculo el punto de control de la curva en y, que es el punto medio del trazo mas un desplazamiento perpendicular proporcional a la distancia

    elapsed = 0.0 # Empiezo a contar el tiempo transcurrido
    last_ix, last_iy = int(round(sx)), int(round(sy)) # Me guardo la ultima posicion del cursor en enteros para evitar que se quede atascado en un pixel
    while elapsed < dur and should_run(): # Mientras no haya terminado el trazo y el hilo siga corriendo
        tau = elapsed / dur # Calculo el tiempo normalizado entre 0 y 1
        s = _min_jerk(tau) # Calculo el avance del trazo segun el modelo de minima aceleracion
        oms = 1.0 - s # Calculo el complemento del avance para usarlo en la formula de la curva de Bezier
        x = oms * oms * sx + 2.0 * oms * s * ctrl_x + s * s * tx # Calculo la nueva posicion x usando la formula de la curva de Bezier cuadratica
        y = oms * oms * sy + 2.0 * oms * s * ctrl_y + s * s * ty # Calculo la nueva posicion y usando la formula de la curva de Bezier cuadratica
        ix, iy = int(round(x)), int(round(y)) # Redondeo la nueva posicion a enteros para mover el cursor
        if ix == last_ix and iy == last_iy: # Si la nueva posicion es igual a la ultima posicion, hago un paso extra en la direccion del trazo para evitar que se quede atascado
            if ux != 0 or uy != 0:
                ix += 1 if ux >= 0 else -1
        USER32.SetCursorPos(ix, iy) # Muevo el cursor a la nueva posicion
        last_ix, last_iy = ix, iy # Me guardo la nueva posicion como la ultima posicion
        dt = random.uniform(STEP_MIN_MS, STEP_MAX_MS) / 1000.0 # Elijo un tiempo de espera aleatorio entre STEP_MIN_MS y STEP_MAX_MS milisegundos
        time.sleep(dt) # Espero el tiempo elegido para simular un movimiento humano
        elapsed += dt # Aumento el tiempo transcurrido

    USER32.SetCursorPos(int(round(tx)), int(round(ty))) # Al final del trazo, muevo el cursor a la posicion final exacta
    state.heading = math.atan2(ty - sy, tx - sx) # Actualizo la direccion del cursor para el siguiente trazo
    state.x, state.y = tx, ty # Actualizo la posicion del cursor para el siguiente trazo

# Funcion para hacer una pausa aleatoria entre 40 y 180 milisegundos
def _human_pause():
    time.sleep(random.uniform(0.04, 0.18))


class HumanImproved(Auxiliary, Thread):

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.config = config
        self.options = options
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
                tx, ty = _pick_next_target(state)
                _human_move_to(state, tx, ty, self._should_run)

                # Actividad de clic (solo si no estoy sobre una consola). Primero
                # pruebo doble clic y, si no, un clic suelto.
                if not cursor_over_console_window():
                    if random.random() < DOUBLE_CLICK_PROB:
                        double_click_mouse()
                    elif random.random() < CLICK_PROB:
                        click_mouse()

                if random.random() < 0.04:
                    _human_pause()

                # Reviso si hay dialogos que confirmar. Como esto es el mismo
                # hilo, tras confirmar el cursor queda donde lo dejo el clic y
                # nada lo mueve hasta la siguiente vuelta.
                USER32.EnumWindows(EnumWindowsProc(_scan_and_confirm_dialogs), 0)

                if cycle % WINDOW_INTERACT_EVERY == 0:
                    USER32.EnumWindows(EnumWindowsProc(handle_window_interaction), 0)

                if cycle % DOC_CLOSE_EVERY == 0:
                    USER32.EnumWindows(EnumWindowsProc(get_document_window), 0)

                if ENABLE_FOREGROUND_SWITCH and cycle % (15 + randoff) == 0:
                    other = INITIAL_HWNDS.copy()
                    with contextlib.suppress(Exception):
                        other.remove(USER32.GetForegroundWindow())
                    if other:
                        USER32.SetForegroundWindow(other[random.randint(0, len(other) - 1)])

                cycle += 1
        except Exception:
            log.exception(traceback.format_exc())