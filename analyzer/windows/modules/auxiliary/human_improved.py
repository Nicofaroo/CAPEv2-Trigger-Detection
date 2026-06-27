#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

log = logging.getLogger(__name__)

EnumWindowsProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)
EnumChildProc = WINFUNCTYPE(c_bool, wintypes.HWND, wintypes.LPARAM)

SM_CXSCREEN = 0
SM_CYSCREEN = 1
SM_CXFULLSCREEN = 16
SM_CYFULLSCREEN = 17

RESOLUTION = {"x": USER32.GetSystemMetrics(SM_CXSCREEN), "y": USER32.GetSystemMetrics(SM_CYSCREEN)}

RESOLUTION_WITHOUT_TASKBAR = {"x": USER32.GetSystemMetrics(SM_CXFULLSCREEN), "y": USER32.GetSystemMetrics(SM_CYFULLSCREEN)}

INITIAL_HWNDS = []

CF_UNICODETEXT = 0x000D

STEP_MIN_MS = 12
STEP_MAX_MS = 18

MAX_TURN_DEG = 18.0

CURVE_K_MAX = 0.07

STROKE_DIST_MIN = 80
STROKE_DIST_MAX = 400

DUR_BASE_S = 0.28
DUR_PER_PX_S = 1.0 / 900.0
DUR_MIN_S = 0.28
DUR_MAX_S = 1.20

EDGE_MARGIN = 12

LEFT_ICON_MARGIN = RESOLUTION_WITHOUT_TASKBAR["x"] // 4

CLICK_PROB = 0.03

WINDOW_INTERACT_EVERY = 40

DOC_CLOSE_EVERY = 60

ENABLE_FOREGROUND_SWITCH = False

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


def get_cursor_position():
    pt = wintypes.POINT()
    USER32.GetCursorPos(byref(pt))
    return (pt.x, pt.y)


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
    KERNEL32.Sleep(20)
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
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    USER32.mouse_event(4, 0, 0, 0, None)


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


def _min_jerk(tau):
    if tau <= 0.0:
        return 0.0
    if tau >= 1.0:
        return 1.0
    return 10.0 * tau ** 3 - 15.0 * tau ** 4 + 6.0 * tau ** 5


def _ang_diff(a, b):
    d = (b - a) % (2.0 * math.pi)
    if d > math.pi:
        d -= 2.0 * math.pi
    return d


class _MovementState:

    def __init__(self):
        x, y = get_cursor_position()
        self.x = float(x)
        self.y = float(y)
        self.heading = None


def _pick_next_target(state):
    w = RESOLUTION_WITHOUT_TASKBAR["x"]
    h = RESOLUTION_WITHOUT_TASKBAR["y"]
    cx = LEFT_ICON_MARGIN + (w - LEFT_ICON_MARGIN) * 0.5
    cy = h * 0.5

    if state.heading is None:
        base = random.uniform(0.0, 2.0 * math.pi)
    else:
        base = state.heading

    edge_x = min(state.x, w - state.x) / (w * 0.5)
    edge_y = min(state.y, h - state.y) / (h * 0.5)
    edge_factor = 1.0 - max(0.0, min(edge_x, edge_y))

    max_turn = math.radians(MAX_TURN_DEG)
    desired_center = math.atan2(cy - state.y, cx - state.x)
    explore_turn = random.uniform(-max_turn, max_turn)

    if edge_factor > 0.6:
        turn = _ang_diff(base, desired_center)
        turn = max(-max_turn, min(max_turn, turn))
    else:
        turn = explore_turn

    angle = base + turn
    dist = random.uniform(STROKE_DIST_MIN, STROKE_DIST_MAX)
    tx = state.x + dist * math.cos(angle)
    ty = state.y + dist * math.sin(angle)

    tx = max(LEFT_ICON_MARGIN, min(w - EDGE_MARGIN, tx))
    ty = max(EDGE_MARGIN, min(h - EDGE_MARGIN, ty))
    return tx, ty


def _human_move_to(state, tx, ty, should_run):
    sx, sy = state.x, state.y
    dx, dy = tx - sx, ty - sy
    dist = math.hypot(dx, dy)
    if dist < 1.0:
        return

    dur = DUR_BASE_S + dist * DUR_PER_PX_S
    dur *= max(0.5, random.gauss(1.0, 0.12))
    dur = max(DUR_MIN_S, min(DUR_MAX_S, dur))

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
        x = oms * oms * sx + 2.0 * oms * s * ctrl_x + s * s * tx
        y = oms * oms * sy + 2.0 * oms * s * ctrl_y + s * s * ty
        ix, iy = int(round(x)), int(round(y))
        if ix == last_ix and iy == last_iy:
            if ux != 0 or uy != 0:
                ix += 1 if ux >= 0 else -1
        USER32.SetCursorPos(ix, iy)
        last_ix, last_iy = ix, iy
        dt = random.uniform(STEP_MIN_MS, STEP_MAX_MS) / 1000.0
        time.sleep(dt)
        elapsed += dt

    USER32.SetCursorPos(int(round(tx)), int(round(ty)))
    state.heading = math.atan2(ty - sy, tx - sx)
    state.x, state.y = tx, ty


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

                if random.random() < CLICK_PROB and not cursor_over_console_window():
                    click_mouse()

                if random.random() < 0.04:
                    _human_pause()

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