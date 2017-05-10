from binaryninja import PluginCommand

import macho_symbols

PluginCommand.register(
    'Mach-O Bind symbols',
    'Generate bind symbols',
    macho_symbols.generate_bind_symbols
)

PluginCommand.register(
    'Mach-O Selrefs symbols',
    'Generate selrefs symbols',
    macho_symbols.generate_selrefs
)

PluginCommand.register(
    'Mach-O Objc function symbols',
    'Generate objc function symbols',
    macho_symbols.generate_function_names
)
