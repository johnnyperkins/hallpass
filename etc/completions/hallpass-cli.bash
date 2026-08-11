# bash completion for hallpass-cli.
#
# Hand-maintained alongside crates/hallpass-cli/src/args.rs. That parser is
# hand-rolled, so there is no generator to regenerate this from: every command,
# flag and value set below has to be kept in step with it by hand.
#
# Rule names are deliberately not completed. Offering them would mean opening
# the daemon socket on every Tab, and that socket is often absent (daemon not
# running) or unreadable (user not in the hallpass group). A completion that
# blocks or spills an error into the prompt is worse than one that stays quiet.

# Fill COMPREPLY with filenames matching $1.
_hallpass_cli_files() {
    # -o filenames so readline escapes spaces and marks directories with '/'.
    compopt -o filenames 2>/dev/null
    mapfile -t COMPREPLY < <(compgen -f -- "$1")
}

_hallpass_cli() {
    local cur prev cmd sub opts i word nargs
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD - 1]}

    local global='--socket --json --color -h --help'

    # The parser strips the global flags wherever they appear, so a command may
    # be preceded by any number of them. Find it by walking the line and
    # skipping those flags (and the values of the two that take one) rather
    # than by assuming it sits at a fixed position.
    #
    # nargs counts every remaining word, not just positional ones, so it is
    # only trusted under 'rules import' and 'rules toggle', which take no flags
    # of their own and therefore cannot have a flag value inflate the count.
    cmd=""
    sub=""
    nargs=0
    i=1
    while ((i < COMP_CWORD)); do
        word=${COMP_WORDS[i]}
        case $word in
        --socket | --color)
            ((i += 2))
            continue
            ;;
        --json | -h | --help)
            ((i += 1))
            continue
            ;;
        esac
        ((nargs += 1))
        case $nargs in
        1) cmd=$word ;;
        2) sub=$word ;;
        esac
        ((i += 1))
    done

    # Value for the flag just typed. Checked before the command dispatch below
    # because --socket and --color are accepted inside any command.
    case $prev in
    --socket)
        _hallpass_cli_files "$cur"
        return
        ;;
    --color)
        COMPREPLY=($(compgen -W 'auto always never' -- "$cur"))
        return
        ;;
    --action)
        COMPREPLY=($(compgen -W 'allow deny reject' -- "$cur"))
        return
        ;;
    --proto)
        COMPREPLY=($(compgen -W 'tcp udp' -- "$cur"))
        return
        ;;
    --verdict)
        COMPREPLY=($(compgen -W 'allow deny reject blocked' -- "$cur"))
        return
        ;;
    --group-by)
        COMPREPLY=($(compgen -W 'exe domain host port rule' -- "$cur"))
        return
        ;;
    --duration)
        # Also accepts a timespan (30s, 5m, 2h, 1d), which cannot be enumerated.
        COMPREPLY=($(compgen -W 'session forever' -- "$cur"))
        return
        ;;
    --parent-exe | --domains-file | --ips-file | --hashes-file)
        _hallpass_cli_files "$cur"
        return
        ;;
    --exe)
        # A path under 'rules add' and 'explain', but a substring to search for
        # under 'events', where a filesystem listing would be misleading.
        [ "$cmd" = events ] || _hallpass_cli_files "$cur"
        return
        ;;
    --last | --domain | --top | --interval | --name | --exe-glob | --exe-sha256 | \
        --dest | --port | --cmdline | --cmdline-contains | --src | --src-port | \
        --iface | --app-id | --user | --priority)
        # Free-form values with nothing sensible to suggest.
        return
        ;;
    esac

    opts=""
    case $cmd in
    "") opts="status doctor sessions run config rules suggest events top watch explain" ;;
    status | doctor | sessions | watch) ;;
    # Everything after `run` belongs to the wrapped command, so completing
    # this CLI's own words there would be wrong.
    run) ;;
    events) opts="--last --no-follow --exe --domain --verdict" ;;
    top) opts="--group-by --interval --top" ;;
    explain)
        opts="--dest --port --proto --exe --cmdline --parent-exe --exe-sha256"
        opts="$opts --domain --user --src --src-port --iface --app-id"
        ;;
    rules)
        case $sub in
        "") opts="--stats add rm toggle export import" ;;
        add)
            opts="--name --action --exe --exe-glob --exe-sha256 --dest --port"
            opts="$opts --domain --user --proto --cmdline-contains --parent-exe"
            opts="$opts --src --src-port --iface --app-id --domains-file --ips-file"
            opts="$opts --hashes-file --duration --priority"
            ;;
        import)
            if ((nargs == 2)); then
                _hallpass_cli_files "$cur"
                return
            fi
            ;;
        toggle)
            # 'rules toggle NAME on|off': the name is left alone, the state is
            # a fixed pair.
            if ((nargs == 3)); then opts="on off"; fi
            ;;
        esac
        ;;
    *)
        # Not a command the parser knows; nothing to suggest.
        return
        ;;
    esac

    COMPREPLY=($(compgen -W "$opts $global" -- "$cur"))
}

complete -F _hallpass_cli hallpass-cli
