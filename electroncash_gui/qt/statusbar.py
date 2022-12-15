from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Callable, Optional

from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QIcon

from electroncash.constants import PROJECT_NAME
from electroncash.i18n import _
from electroncash.plugins import run_hook
from electroncash.util import Weak

from .popup_widget import KillPopupLabel, ShowPopupLabel
from .util import ColorScheme

if TYPE_CHECKING:
    from . import ElectrumGui


class StatusBarButton(QtWidgets.QPushButton):
    def __init__(self, icon, tooltip, func: Optional[Callable] = None):
        QtWidgets.QPushButton.__init__(self, icon, "")
        self.setToolTip(tooltip)
        self.setFlat(True)
        self.setMaximumWidth(25)
        self.clicked.connect(self.onPress)
        self.func = func
        self.setIconSize(QSize(25, 25))
        self.setCursor(Qt.PointingHandCursor)

    def onPress(self, checked=False):
        """Drops the unwanted PyQt5 "checked" argument"""
        if self.func is not None:
            self.func()

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Return and self.func is not None:
            self.func()
        else:
            super().keyPressEvent(e)


class StatusBar(QtWidgets.QStatusBar):
    def __init__(self, gui_object: ElectrumGui):
        self.gui_object = Weak.ref(gui_object)

        super().__init__()
        self.setFixedHeight(35)

        self.balance_label = QtWidgets.QLabel("")
        self.addWidget(self.balance_label)

        self._search_box_spacer = QtWidgets.QWidget()
        self._search_box_spacer.setFixedWidth(6)  # 6 px spacer
        self.search_box = QtWidgets.QLineEdit()
        self.search_box.setPlaceholderText(
            _("Search wallet, {key}F to hide").format(
                key="Ctrl+" if sys.platform != "darwin" else "⌘"
            )
        )
        self.search_box.hide()
        self.addPermanentWidget(self.search_box, 1)

        self.update_available_button = StatusBarButton(
            QIcon(":icons/electrumABC-update.svg"),
            _("Update available, click for details"),
        )
        self.update_available_button.setStatusTip(
            _(f"An {PROJECT_NAME} update is available")
        )
        # if hidden now gets unhidden by on_update_available when a new version comes
        # in
        self.update_available_button.setVisible(
            bool(self.gui_object().new_version_available)
        )
        self.addPermanentWidget(self.update_available_button)

        self.lock_icon = QIcon()
        self.password_button = StatusBarButton(self.lock_icon, _("Password"))
        self.addPermanentWidget(self.password_button)

        self.addr_converter_button = StatusBarButton(
            self.cashaddr_icon(),
            _("Toggle CashAddr Display"),
        )
        self.addr_converter_button.clicked.connect(self.toggle_cashaddr_status_bar)
        self.update_cashaddr_icon()
        self.addPermanentWidget(self.addr_converter_button)
        self.addr_converter_button.setHidden(
            self.gui_object().is_cashaddr_status_button_hidden()
        )
        self.gui_object().cashaddr_status_button_hidden_signal.connect(
            self.addr_converter_button.setHidden
        )

        self.preferences_button = StatusBarButton(
            QIcon(":icons/preferences.svg"), _("Preferences")
        )
        self.addPermanentWidget(self.preferences_button)

        self.seed_button = StatusBarButton(QIcon(":icons/seed.png"), _("Seed"))
        self.addPermanentWidget(self.seed_button)

        self.status_button = StatusBarButton(
            QIcon(":icons/status_disconnected.svg"),
            _("Network"),
        )
        self.addPermanentWidget(self.status_button)

        run_hook("create_status_bar", self)

    def cashaddr_icon(self):
        if self.gui_object().is_cashaddr():
            return QIcon(":icons/tab_converter.svg")
        else:
            return QIcon(":icons/tab_converter_bw.svg")

    def update_cashaddr_icon(self):
        self.addr_converter_button.setIcon(self.cashaddr_icon())
        self.addr_converter_button.setStatusTip(self.cashaddr_status_tip())

    def cashaddr_status_tip(self):
        if self.gui_object().is_cashaddr():
            return _("Address Format") + " - " + _("CashAddr")
        else:
            return _("Address Format") + " - " + _("Legacy")

    def toggle_search(self):
        self.search_box.setHidden(not self.search_box.isHidden())
        if not self.search_box.isHidden():
            self.balance_label.setHidden(True)
            self.insertWidget(0, self._search_box_spacer)
            self._search_box_spacer.show()
            self.search_box.setFocus(True)
            if self.search_box.text():
                self.search_box.textChanged.emit(self.search_box.text())
        else:
            self._search_box_spacer.hide()
            self.removeWidget(self._search_box_spacer)
            self.balance_label.setHidden(False)
            self.search_box.textChanged.emit("")

    def toggle_cashaddr_status_bar(self):
        self.gui_object().toggle_cashaddr()
        self.showMessage(self.cashaddr_status_tip(), 2000)

    def on_update_available(self, b):
        self.update_available_button.setVisible(bool(b))

        # The popup label won't really be shown unless this window is
        # on top.. but regardless we give each label a unique internal name
        # so they dont interfere with each other.
        lblName = f"UpdateAvailable_{id(self)}"

        if b:
            ShowPopupLabel(
                name="Update Available",
                text=f'<center><b>{_("Update Available")}</b><br>'
                f'<small>{_("Click for details")}</small></center>',
                target=self.update_available_button,
                timeout=20000,
                onClick=self.update_available_button.click,
                onRightClick=self.update_available_button.click,
                dark_mode=ColorScheme.dark_scheme,
            )
        else:
            # Immediately kills any extant labels
            KillPopupLabel(lblName)

    def update_lock_icon(self, wallet_has_password: bool):
        icon = (
            QIcon(":icons/lock.svg")
            if wallet_has_password
            else QIcon(":icons/unlock.svg")
        )
        tip = _("Wallet Password") + " - "
        tip += _("Enabled") if wallet_has_password else _("Disabled")
        self.password_button.setIcon(icon)
        self.password_button.setStatusTip(tip)

    def update_buttons_on_seed(
        self, wallet_has_seed: bool, wallet_may_have_password: bool
    ):
        self.seed_button.setVisible(wallet_has_seed)
        self.password_button.setVisible(wallet_may_have_password)
