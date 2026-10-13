from . import (
    info01_search,
    info02_server,
    info03_metafiles,
    info04_active,
    info05_content,
    info06_entrypoints,
    info07_spider,
    info08_framework,
    info09_app,
    info10_arch,
)

MODULES = [
    info01_search,
    info02_server,
    info03_metafiles,
    info04_active,
    info05_content,
    info06_entrypoints,
    info07_spider,
    info08_framework,
    info09_app,
    info10_arch,
]


def by_id(wstg_id):
    for mod in MODULES:
        if mod.WSTG_ID == wstg_id:
            return mod
    return None
