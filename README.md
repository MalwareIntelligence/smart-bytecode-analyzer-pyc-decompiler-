🔬 Smart Bytecode Analyzer v7.0






Near‑perfect reconstruction of Python source code from compiled .pyc bytecode files.

A powerful modern tool for analyzing and reconstructing Python bytecode, supporting Python 3.0 through 3.16, featuring an intuitive GUI and advanced static analysis capabilities.

⚠️ Important Notice

This project is intended strictly for educational purposes, malware research, reverse engineering, and security analysis.
Use only on files you are legally permitted to inspect.
No decompiler can perfectly restore original source exactly as written before compilation.
Version mismatch will cause errors.

✨ Features
Core Capabilities

🎯 Near‑Perfect Code Reconstruction – VM‑based bytecode interpretation

🐍 Wide Python Support – Python 3.0 to 3.16 Future proof

🔄 Control Flow Analysis – Loops, exceptions, conditionals

📊 Static Analysis – Functions, classes, imports extraction

✨ Deobfuscator - Helps with reconstruction by deobfuscating the file


🎨 Modern GUI – Built with CustomTkinter

⚡ Batch Processing – Whole directories at once

💾 Multiple Export Formats – Python / HTML / Markdown / JSON

Advanced Features

Stack simulation & execution tracking

Control Flow Graph (CFG) generation

Bytecode pattern recognition

Post‑processing cleanup

Caching for performance

Profiling & analysis metrics

🚀 Quick Start
Installation
git clone https://github.com/MalwareIntelligence/smart-bytecode-analyzer.git
cd smart-bytecode-analyzer
pip install -r requirements.txt
python analyzer.py

🖥️ Usage
GUI Mode (Default)
python analyzer.py

Command Line – Single File
python analyzer.py --file input.pyc --output output.py

Batch Processing
python analyzer.py --batch /path/to/pyc --output-dir ./reconstructed

Validate PYC
python analyzer.py --validate input.pyc

Export HTML
python analyzer.py --file input.pyc --output report.html --format html

📋 Requirements

Python 3.8+

customtkinter >= 5.0.0

Standard modules: dis, marshal, tkinter

🎯 Use Cases

🔍 Malware analysis and inspection

🛠 Reverse engineering compiled Python apps

📦 Recover lost or damaged source

📘 Learn Python bytecode & internals

🧪 Debug compiled behavior

📖 Architecture

Core Engine – Bytecode simulation

Static Analyzer – Extract code structure

Reconstruct Engine – Source reconstruction

GUI Application – Interactive viewer

Utils – Batch, cache, export

CLI – Scriptable interface

🐍 Supported Python Versions
Version	Status
3.0 – 3.6	✅ Supported
3.7 – 3.10	✅ Supported
3.11.8	✅ Fully Tested
3.12	✅ Supported
3.13	✅ Supported
Early Builds  ✅ Supported
non out versions ✅ Supported
🛠️ Project Structure
smart-bytecode-analyzer/
├── analyzer.py
├── requirements.txt
├── README.md
├── LICENSE
├── docs/
│   └── screenshot.png
└── tests/

🐛 Known Limitations

Obfuscated bytecode may not fully reconstruct

Dynamic code (eval, exec) cannot be fully restored

Complex decorators may lose original formatting

Some Python 3.14+ features may need updates

📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

📧 Contact & Issues

For bugs, feature requests, or support:

📧 malware.intelligence@gmx.de

GitHub: https://github.com/MalwareIntelligence

🌟 Final Note

If you find this tool useful, please consider ⭐ starring the repository!

Made with ❤️ for the Python and security community
