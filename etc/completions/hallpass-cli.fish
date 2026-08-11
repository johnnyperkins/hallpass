# fish completion for hallpass-cli.
#
# Hand-maintained alongside crates/hallpass-cli/src/args.rs. That parser is
# hand-rolled, so there is no generator to regenerate this from: every command,
# flag and value set below has to be kept in step with it by hand.
#
# Rule names are deliberately not completed. Offering them would mean opening
# the daemon socket on every Tab, and that socket is often absent (daemon not
# running) or unreadable (user not in the hallpass group). A completion that
# blocks or spills an error into the prompt is worse than one that stays quiet.

# Command words typed so far, one per line.
#
# Flags are dropped, and so are the values of the two global flags that take
# one, so that "hallpass-cli --socket /tmp/x.sock <TAB>" still knows no command
# has been given. Values of per-command flags are not dropped, so only the
# first two words may be read as command and subcommand; the third is only read
# under 'rules toggle' and 'rules import', which take no flags of their own.
function __hallpass_cli_words
    set -l skip 0
    set -l tokens (commandline -opc)
    set -e tokens[1]
    for token in $tokens
        if test $skip -eq 1
            set skip 0
            continue
        end
        switch $token
            case --socket --color
                set skip 1
            case '-*'
                # A flag, not a command word.
            case '*'
                echo $token
        end
    end
end

# True when the words typed so far start with $argv.
function __hallpass_cli_in
    set -l words (__hallpass_cli_words)
    if test (count $words) -lt (count $argv)
        return 1
    end
    for i in (seq (count $argv))
        if test "$words[$i]" != "$argv[$i]"
            return 1
        end
    end
    return 0
end

# True when the words typed so far are exactly $argv.
function __hallpass_cli_is
    if test (count (__hallpass_cli_words)) -ne (count $argv)
        return 1
    end
    __hallpass_cli_in $argv
end

# Nothing here takes a bare filename except where said so below.
complete -c hallpass-cli -f

# Commands.
complete -c hallpass-cli -n '__hallpass_cli_is' -a status -d 'Show daemon statistics'
complete -c hallpass-cli -n '__hallpass_cli_is' -a rules -d 'List, add, remove, toggle, export or import rules'
complete -c hallpass-cli -n '__hallpass_cli_is' -a events -d 'Stream connection events until Ctrl-C'
complete -c hallpass-cli -n '__hallpass_cli_is' -a top -d 'Live aggregate view of connection activity'
complete -c hallpass-cli -n '__hallpass_cli_is' -a watch -d 'Interactively answer connection prompts'
complete -c hallpass-cli -n '__hallpass_cli_is' -a explain -d 'Say what policy would do with a hypothetical connection'

# Global options. The parser strips these wherever they appear, so they are
# offered inside every command rather than only before the command word.
complete -c hallpass-cli -l socket -r -F -d 'Daemon socket path'
complete -c hallpass-cli -l json -d 'Machine-readable JSON output'
complete -c hallpass-cli -l color -x -a 'auto always never' -d 'When to colorize output'
complete -c hallpass-cli -s h -l help -d 'Show usage and exit'

# rules
complete -c hallpass-cli -n '__hallpass_cli_is rules' -l stats -d 'Add per-rule hit counts to the listing'
complete -c hallpass-cli -n '__hallpass_cli_is rules' -a add -d 'Add a rule'
complete -c hallpass-cli -n '__hallpass_cli_is rules' -a rm -d 'Delete a rule'
complete -c hallpass-cli -n '__hallpass_cli_is rules' -a toggle -d 'Enable or disable a rule'
complete -c hallpass-cli -n '__hallpass_cli_is rules' -a export -d 'Write the ruleset to stdout as one TOML document'
complete -c hallpass-cli -n '__hallpass_cli_is rules' -a import -d 'Add every rule in such a document'

# rules toggle NAME on|off: the name is left alone, the state is a fixed pair.
complete -c hallpass-cli -n '__hallpass_cli_in rules toggle; and test (count (__hallpass_cli_words)) -eq 3' -a 'on off' -d 'New enabled state'

# rules import PATH
complete -c hallpass-cli -n '__hallpass_cli_is rules import' -F -d 'Rule document'

# rules add
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l name -x -d 'Rule name (required)'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l action -x -a 'allow deny reject' -d 'Action on match (required)'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l exe -r -F -d 'Exact executable path'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l exe-glob -x -d 'Glob matched against the executable path'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l exe-sha256 -x -d 'SHA-256 of the executable (64 hex digits)'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l dest -x -d 'Destination IP address or CIDR block'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l port -x -d 'Destination port'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l domain -x -d 'Domain, exact or *.suffix'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l user -x -a '(__fish_complete_users)' -d 'UID of the initiating process'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l proto -x -a 'tcp udp' -d 'Transport protocol'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l cmdline-contains -x -d 'Substring of the process command line'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l parent-exe -r -F -d 'Exact executable path of the parent process'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l src -x -d 'Source IP address or CIDR block'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l src-port -x -d 'Source port'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l iface -x -a '(__fish_print_interfaces)' -d 'Outbound network interface'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l app-id -x -d 'Packaged application (flatpak:<id> or snap:<name>)'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l domains-file -r -F -d 'File of domains, hosts format or one per line'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l ips-file -r -F -d 'File of destination IPs or CIDRs, one per line'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l hashes-file -r -F -d 'File of executable SHA-256 hashes, one per line'
# --duration also takes a timespan such as 30s, 5m, 2h or 1d.
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l duration -x -a 'session forever' -d 'Rule lifetime'
complete -c hallpass-cli -n '__hallpass_cli_in rules add' -l priority -x -d 'Priority, higher wins'

# events
complete -c hallpass-cli -n '__hallpass_cli_in events' -l last -x -d 'Replay the last N decided connections before streaming'
complete -c hallpass-cli -n '__hallpass_cli_in events' -l no-follow -d 'With --last, print the replay and exit'
# A substring to search for, not a path, so no file completion here.
complete -c hallpass-cli -n '__hallpass_cli_in events' -l exe -x -d 'Only events whose executable path contains this substring'
complete -c hallpass-cli -n '__hallpass_cli_in events' -l domain -x -d 'Only events whose destination domain contains this substring'
complete -c hallpass-cli -n '__hallpass_cli_in events' -l verdict -x -a 'allow deny reject blocked' -d 'Only these verdicts'

# top
complete -c hallpass-cli -n '__hallpass_cli_in top' -l group-by -x -a 'exe domain host port rule' -d 'What each row counts'
complete -c hallpass-cli -n '__hallpass_cli_in top' -l interval -x -d 'Redraw period in seconds'
complete -c hallpass-cli -n '__hallpass_cli_in top' -l top -x -d 'Rows to show'

# explain
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l dest -x -d 'Destination IP address (required)'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l port -x -d 'Destination port (required)'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l proto -x -a 'tcp udp' -d 'Transport protocol'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l exe -r -F -d 'Executable path of the hypothetical process'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l cmdline -x -d 'Its full command line'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l parent-exe -r -F -d 'Executable path of its parent'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l exe-sha256 -x -d 'SHA-256 for hash operands (64 hex digits)'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l domain -x -d 'Destination domain as DNS snooping would annotate it'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l user -x -a '(__fish_complete_users)' -d 'UID of the hypothetical process'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l src -x -d 'Source IP address'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l src-port -x -d 'Source port'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l iface -x -a '(__fish_print_interfaces)' -d 'Outbound network interface'
complete -c hallpass-cli -n '__hallpass_cli_in explain' -l app-id -x -d 'Packaged application (flatpak:<id> or snap:<name>)'
