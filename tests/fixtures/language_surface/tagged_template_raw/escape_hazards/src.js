// Escape hazards inside tagged-template raw chunks: a backtick, an
// escaped dollar-brace (`\${`), and a trailing lone backslash. The
// decompiler's TaggedTemplate Display must defensively escape all three
// so the emitted JS re-parses through hermesc.

function tag(strings, x) {
    return strings.raw.join("|") + "@" + x;
}

print(tag`has \`backtick and \${literal}${42}ends with \\`);
