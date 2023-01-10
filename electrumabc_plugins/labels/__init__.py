from electroncash.constants import PROJECT_NAME
from electroncash.i18n import _

fullname = _("LabelSync")
description = [
    _(
        "Save your wallet labels on a remote server, and synchronize "
        f"them across multiple devices where you use {PROJECT_NAME}."
    ),
    _(
        "Labels, transactions IDs and addresses are encrypted before they"
        " are sent to the remote server."
    ),
]
available_for = ["qt"]
