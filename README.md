# Mach-O Symbols Generator
Author: **Bambu**

_Creates symbols and renames functions in mach-o binaries_

## Description:
Creates symbols and renames functions in mach-o binaries in order to aid reversing. This is inteded only for x86_64 Mach-O binaries and has not been tested on x86. Also, \"Mach-O Bind Symbols\" requires `dyldinfo`

Before running:

![Before Image](images/before.png?raw=true "Before running plugins")

After running:

![After Image](images/after.png?raw=true "After running plugins")

To install this plugin, navigate to your Binary Ninja plugins directory, and run

```git clone https://github.com/bambu/binaryninja-machosymbols.git machosymbols```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * dev (Personal) - 1.0.dev-730
 * dev (Commercial) - 1.0.dev-730
 
## TODO
 * Create more symbols
 * Add support for x86
 * Actually implement the Bind symbols and remove reliance on `dyldinfo`

## License

This plugin is released under a [MIT](LICENSE) license.


