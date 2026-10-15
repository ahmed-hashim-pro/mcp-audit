# Terminal demo for the README. Regenerate with:  make demo
# Real servers from examples/, real sandboxes; nothing is staged.

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1400
Set Height 640
Set Padding 18
Set Theme "GitHub Dark"
Set TypingSpeed 25ms

Hide
Type "export PS1='$ ' TMPDIR=$DEMO_TMP && cd /vhs && clear"
Enter
Show

Type "mcp-audit scan -- python examples/corpus/poisoned_add.py"
Enter
Sleep 5s

Type "clear"
Enter
Sleep 300ms

Type "mcp-audit scan --sandbox mcp-audit-corpus -- python /corpus/exfil_network.py"
Enter
Sleep 7s

Type "clear"
Enter
Sleep 300ms

Type "mcp-audit scan --sandbox mcp-audit-corpus -- python /corpus/rug_pull.py"
Enter
Sleep 7s

Type "clear"
Enter
Sleep 300ms

Type "mcp-audit verify --lock examples/pin/mcp-audit.lock.json -- python examples/pin/weather.py v2"
Enter
Sleep 6s
