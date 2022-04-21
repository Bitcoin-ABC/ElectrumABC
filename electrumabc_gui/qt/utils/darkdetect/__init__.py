#-----------------------------------------------------------------------------
#  Copyright (C) 2019 Alberto Sottile
#
#  Distributed under the terms of the 3-clause BSD License.
#-----------------------------------------------------------------------------

__version__ = '0.1.1'

import sys
import platform

if sys.platform != "darwin":
    from ._dummy import isDark, isLight, theme
else:
    from distutils.version import LooseVersion as V
    if V(platform.mac_ver()[0]) < V("10.14"):
        from ._dummy import isDark, isLight, theme
    else:
        from ._detect import isDark, isLight, theme
    del V

del sys, platform
