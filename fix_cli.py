#!/usr/bin/env python3
import sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    content = f.read()
content = content.replace('print(f"  {Fore.CYAN}{comment}{Style.RESET_ALL}))', 'print(f"  {Fore.CYAN}{comment}{Style.RESET_ALL}")')
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed')
