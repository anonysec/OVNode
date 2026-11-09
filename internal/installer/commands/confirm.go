package commands

import (
	"bufio"
	"os"
	"strings"
)

// confirmWord mirrors lib.sh confirm_word: typed answer, empty = no.
// In non-TTY it refuses, like lib.sh confirm.
func confirmWord(word string) bool {
	if !isTTY() {
		return false
	}
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line) == word
}

// confirmOne mirrors lib.sh confirm n (no default).
func confirmOne(prompt string) bool {
	if !isTTY() {
		return false
	}
	r := bufio.NewReader(os.Stdin)
	line, _ := r.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
