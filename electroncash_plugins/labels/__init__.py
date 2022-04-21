from electrumabc.i18n import _
from electrumabc.constants import PROJECT_NAME

fullname = _('LabelSync')
description = [
    _("Save your wallet labels on a remote server, and synchronize "
      f"them across multiple devices where you use {PROJECT_NAME}."),
    _("Labels, transactions IDs and addresses are encrypted before they"
      " are sent to the remote server.")
]
available_for = ['qt']
