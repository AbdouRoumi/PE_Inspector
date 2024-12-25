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
Reading ....... sample.exe
[+] "sample.exe" Read At : 0x12345678 Of Size : 102400

#####################[ FILE HEADER ]#####################
Image file detected Executable as: EXE
The file architecture is : x64
Number Of Sections : 5
...
```

## Contributing

Contributions are welcome! If you encounter issues or have ideas for improvements, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

---
**Happy Inspecting! 🛡️**

> *"Understanding the PE format is the first step to mastering Windows internals."*
