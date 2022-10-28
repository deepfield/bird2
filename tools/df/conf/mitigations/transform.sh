#!/bin/bash
# sequence of replacements
#  - comments
#  - prefix
#  - match terms
#  - action (includes terminating } for prefix)
sed -e '{s|//|#|g}' \
    -e '{s#protocol \[\(.\+\)\];#\n        proto \1;#g}' \
    -e '{s#protocol#\n         proto#g}' \
    -e '{s#source-address#\n         src#g}'  \
    -e '{s#destination-address#\n         dst#g}'  \
    -e '{s#tcp-flags \(0x[[:xdigit:]]\+\);#\n        tcp flags \1/0xfff;#g}' \
    -e '{s#source-port#\n         sport#g}' \
    -e '{s#destination-port#\n         dport#g}' \
    -e '{s#is-fragment#\n        fragment is_fragment#g}' \
    -e '{s#packet-length#\n        length#g}' \
    -e '{s#route\s[0-9]\+\s[{]\smatch#protocol static \{\n    flow4 \{ table masterflow4; \};\n\n    route flow4#}' \
    -e '{s#[}]\sthen\s{\sdiscard;\s}\s}#\n\        } \{\n         bgp_ext_community.add( (generic, 0x80000006, 0) );\n     \};\n}#g}'

