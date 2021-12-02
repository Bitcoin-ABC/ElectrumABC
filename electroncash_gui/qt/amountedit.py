# -*- coding: utf-8 -*-

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QPainter
from PyQt5 import QtWidgets

from decimal import Decimal
from electroncash.util import format_satoshis_plain
from electroncash.constants import BASE_UNITS_BY_DECIMALS
from .util import ColorScheme


class MyLineEdit(QtWidgets.QLineEdit):
    frozen = pyqtSignal()

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setFrame(not b)
        self.frozen.emit()


class AmountEdit(MyLineEdit):
    shortcut = pyqtSignal()

    def __init__(self, base_unit: str, is_int=False, parent=None):
        QtWidgets.QLineEdit.__init__(self, parent)
        # This seems sufficient for 10,000 MXEC amounts with two decimals
        self.setFixedWidth(160)
        self.base_unit: str = base_unit
        self.decimal_point: int = 2
        self.textChanged.connect(self.numbify)
        self.is_int = is_int
        self.is_shortcut = False

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.shortcut.emit()
            return
        pos = self.cursorPosition()
        chars = '0123456789'
        if not self.is_int: chars +='.'
        s = ''.join([i for i in text if i in chars])
        if not self.is_int:
            if '.' in s:
                p = s.find('.')
                s = s.replace('.', '')
                s = s[:p] + '.' + s[p:p + self.decimal_point]
        self.setText(s)
        # setText sets Modified to False.  Instead we want to remember
        # if updates were because of user modification.
        self.setModified(self.hasFocus())
        self.setCursorPosition(pos)

    def paintEvent(self, event):
        QtWidgets.QLineEdit.paintEvent(self, event)
        if self.base_unit:
            panel = QtWidgets.QStyleOptionFrame()
            self.initStyleOption(panel)
            textRect = self.style().subElementRect(QtWidgets.QStyle.SE_LineEditContents, panel, self)
            textRect.adjust(2, 0, -10, 0)
            painter = QPainter(self)
            painter.setPen(ColorScheme.GRAY.as_color())
            painter.drawText(textRect, Qt.AlignRight | Qt.AlignVCenter, self.base_unit)

    def get_amount(self):
        try:
            return (int if self.is_int else Decimal)(self.text())
        except (ValueError, ArithmeticError):
            return None


class XECAmountEdit(AmountEdit):

    def __init__(self, decimal_point: int, is_int=False, parent=None):
        if decimal_point not in BASE_UNITS_BY_DECIMALS:
            raise Exception('Unknown base unit')
        self._base_unit: str = BASE_UNITS_BY_DECIMALS[decimal_point]
        AmountEdit.__init__(self, self._base_unit, is_int, parent)
        self.decimal_point = decimal_point

    def get_amount(self):
        try:
            x = Decimal(self.text())
        except ArithmeticError:
            return None
        p = pow(10, self.decimal_point)
        return int(p * x)

    def setAmount(self, amount):
        if amount is None:
            # Space forces repaint in case units changed
            self.setText(" ")
        else:
            self.setText(format_satoshis_plain(amount, self.decimal_point))


class XECSatsByteEdit(XECAmountEdit):
    def __init__(self, parent=None):
        XECAmountEdit.__init__(self, decimal_point=2, is_int=False, parent=parent)
        self._base_unit = 'sats/B'

    def get_amount(self):
        try:
            x = float(Decimal(self.text()))
        except (ValueError, ArithmeticError):
            return None
        return x if x > 0.0 else None

    def setAmount(self, amount):
        if amount is None:
            # Space forces repaint in case units changed
            self.setText(" ")
        else:
            self.setText(str(round(amount * 100.0) / 100.0))
