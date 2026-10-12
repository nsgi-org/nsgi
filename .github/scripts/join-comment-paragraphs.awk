function flush() {
    if (held != "") print held
    held = ""
    held_prefix = ""
}

function keep() {
    flush()
    print
}

function indent(s,    i, c, col) {
    col = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == " ") col++
        else if (c == "\t") col += 4 - col % 4
        else break
    }
    return col
}

{
    if (!match($0, /^[ \t]*\/\/+!?/)) { keep(); next }
    prefix = substr($0, 1, RLENGTH)
    text = substr($0, RLENGTH + 1)
    sub(/^ /, "", text)

    if (text ~ /^```/) { fence = !fence; keep(); next }
    if (fence || text == "" || text ~ /^(#|\|)/) { keep(); next }
    if (prefix == held_prefix) {
        if (text !~ /^[ \t]*([-+*]|[0-9]+[.)]) /) {
            sub(/^[ \t]+/, "", text)
            held = held " " text
            next
        }
    } else if (indent(text) >= 4) { keep(); next }
    flush()
    held = $0
    held_prefix = prefix
}

END { flush() }
