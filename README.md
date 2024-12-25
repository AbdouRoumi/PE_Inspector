# PE Inspector

## [![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=2000&pause=1000&width=435&lines=Welcome+to+PE+Inspector+Repo!!!;Analyze+PE+files+like+a+pro;Understand+EXE+and+DLL+structures;Your+gateway+to+PE+internals)](https://git.io/typing-svg)

## Overview

Welcome to the **PE Inspector** repository! This project is a tool for inspecting and analyzing Portable Executable (PE) files, including EXE, DLL, and SYS files. It provides detailed insights into the file headers, sections, and data directories, making it an essential utility for reverse engineers, malware analysts, and security enthusiasts.

This tool reads and parses PE files, displaying critical information such as file architecture, entry points, sections, and directory tables.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Contributing](#contributing)
- [License](#license)

## Features

- Parses DOS, NT, and Optional headers.
- Displays file architecture (x32/x64).
- Analyzes PE sections and their characteristics.
- Shows data directories (Export, Import, Resource, TLS, IAT).
- Provides RVA (Relative Virtual Address) and raw address details.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/PE-Inspector.git
   ```
2. Open the project in Visual Studio.
3. Build the project in Debug or Release mode.

## Usage

1. Compile the program.
2. Run it from the command line:
   ```cmd
   PEInspector.exe <path_to_pe_file>
   ```
3. Inspect the detailed output provided by the tool.

## Example Output

```
Reading ....... .\Exe_For_Test.exe
[+] DONE
[+] ".\Exe_For_Test.exe" Read At : 0x000002483B227030 Of Size : 61952

        #####################[ FILE HEADER ]#####################

Image file detected Executable as: EXE
The file architecture is : x64
Number Of Sections : 10
Size Of The Optional Header : 240 Byte

        #####################[ OPTIONAL HEADER ]#####################

Size Of Code Section : 32256
Address Of Code Section : 0x000002483B228030
                [RVA : 0x00001000]
Size Of Initialized Data : 30720
Size Of Unitialized Data : 0
Preferable Mapping Address : 0x0000000140000000
Required Version : 6.0
Address Of The Entry Point : 0x000002483B23828D
                [RVA : 0x0001125D]
Size Of The Image : 151552
File CheckSum : 0x00000000
Number of entries in the DataDirectory array : 16

        #####################[ DIRECTORIES ]#####################

[*] Export Directory At 0x000002483B227030 Of Size : 0
                [RVA : 0x00000000]
[*] Import Directory At 0x000002483B247420 Of Size : 100
                [RVA : 0x000203F0]
[*] Resource Directory At 0x000002483B24A030 Of Size : 1084
                [RVA : 0x00023000]
[*] Exception Directory At 0x000002483B244030 Of Size : 7332
                [RVA : 0x0001D000]
[*] Exception Directory At 0x000002483B24B030 Of Size : 100
                [RVA : 0x00024000]
[*] TLS Directory At 0x000002483B227030 Of Size : 0
                [RVA : 0x00000000]
[*] IAT Directory At 0x000002483B247030 Of Size : 1008
                [RVA : 0x00020000]

        #####################[ SECTIONS ]#####################

Name : .textbss
        Size : 0
        RVA : 0x00001000
        Address : 0x000002483B228030
        Relocations : 0
        Permissions : PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READWRITE

Name : .text
        Size : 32256
        RVA : 0x00011000
        Address : 0x000002483B238030
        Relocations : 0
        Permissions : PAGE_READONLY | PAGE_EXECUTE | PAGE_EXECUTE_READWRITE

Name : .rdata
        Size : 11776
        RVA : 0x00019000
        Address : 0x000002483B240030
        Relocations : 0
        Permissions : PAGE_READONLY |

Name : .data
        Size : 512
        RVA : 0x0001C000
        Address : 0x000002483B243030
        Relocations : 0
        Permissions : PAGE_READONLY | PAGE_READWRITE |

Name : .pdata
        Size : 8704
        RVA : 0x0001D000
        Address : 0x000002483B244030
        Relocations : 0
        Permissions : PAGE_READONLY |

Name : .idata
        Size : 4096
        RVA : 0x00020000
        Address : 0x000002483B247030
        Relocations : 0
        Permissions : PAGE_READONLY |

Name : .msvcjmc├
        Size : 512
        RVA : 0x00021000
        Address : 0x000002483B248030
        Relocations : 0
        Permissions : PAGE_READONLY | PAGE_READWRITE |

Name : .00cfg
        Size : 512
        RVA : 0x00022000
        Address : 0x000002483B249030
        Relocations : 0
        Permissions : PAGE_READONLY |

Name : .rsrc
        Size : 1536
        RVA : 0x00023000
        Address : 0x000002483B24A030
        Relocations : 0
        Permissions : PAGE_READONLY |

Name : .reloc
        Size : 1024
        RVA : 0x00024000
        Address : 0x000002483B24B030
        Relocations : 0
        Permissions : PAGE_READONLY |

[#] Press <Enter> To Quit ...
...
```

## Contributing

Contributions are welcome! If you encounter issues or have ideas for improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE.txt).

---
**Happy Inspecting! 🛡️**

> *"Understanding the PE format is the first step to mastering Windows internals."*
