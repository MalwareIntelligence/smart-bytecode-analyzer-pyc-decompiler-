Smart Bytecode Analyzer v7.0

This tool lets you reconstruct Python source code from compiled .pyc files almost perfectly. It supports Python 3.0 through 3.16, comes with a modern GUI, and offers advanced static analysis features.

Important:
This project is intended only for educational purposes, malware research, reverse engineering, and security analysis. Use it only on files you are legally allowed to inspect. No decompiler can fully restore the original source code. Version mismatches may cause errors.

Features

Core Capabilities:

Near-perfect code reconstruction using VM-based bytecode interpretation
Wide Python support: 3.0–3.16
Control flow analysis: loops, conditionals, exceptions
Static analysis: extract functions, classes, and imports
Deobfuscator to help make obfuscated code readable

User Interface:

Modern GUI built with CustomTkinter
Batch processing for entire directories
Export to Python, HTML, Markdown, or JSON

Advanced Features:

Stack simulation and execution tracking
Control Flow Graph (CFG) generation
Bytecode pattern recognition
Post-processing cleanup
Caching for better performance
Profiling and analysis metrics
Quick Start

Installation:

git clone https://github.com/MalwareIntelligence/smart-bytecode-analyzer.git
cd smart-bytecode-analyzer
pip install -r requirements.txt
python analyzer.py

Usage:

GUI mode (default):

python analyzer.py

Command line – single file:

python analyzer.py --file input.pyc --output output.py

Batch processing:

python analyzer.py --batch /path/to/pyc --output-dir ./reconstructed

Validate a .pyc file:

python analyzer.py --validate input.pyc

Export as HTML:

python analyzer.py --file input.pyc --output report.html --format html
