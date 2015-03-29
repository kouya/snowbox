package maildrop

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

/* Represents one message inside the maildrop */
type Message struct {
	body []string
	deleted bool
	size int
	uidl string
}

func LoadMaildrop(user string, maildir string) (messages []Message, success bool, clientMessage string, logMessage string) {
	success = true
	messages = make([]Message, 0, 100)
	maildrop := fmt.Sprintf("%s/%s", maildir, user)
	file, err := os.OpenFile(maildrop, syscall.O_RDWR, 0660)
	defer file.Close()
	if err != nil {
		clientMessage = "Could not load messages from mailbox. This is fatal. Self-destruct in 10..."
		logMessage = fmt.Sprintf("Could not load mailbox for %s.", user)
		success = false
		return
	}

	// TODO
	// Lock user mailbox and disconnect if lock couldn't be acquired
	// if acquireLocks(c, int(file.Fd())) == false {
		// sendClientReply(c, false, []string{"-ERR Could not lock mailbox. Is another POP3 session active?"})
		// if loglevel >= 1 {
		// 	log_str := fmt.Sprintf("Could not lock mailbox for %s.", user)
		// 	logEvent(c, log_str, 1)
		// }
		// success = false
		// return
	// }

	reader := bufio.NewReader(file)
	i := 0
	blankline := 1
	for {
		line, read_err := reader.ReadString('\n')
		_ = read_err
		next_bites, peek_err := reader.Peek(5)
		nextline := string(next_bites)
		_ = peek_err
		if line == "" {
			// End of input
			break
		}
		if strings.Index(line, "From ") == 0 && blankline == 1 {
			// Start of new message
			m := Message{}
			m.body = make([]string, 0, 500)
			m.body = append(m.body, line)
			m.size = len(line)
			m.deleted = false
			h := md5.New()
			io.WriteString(h, line)
			m.uidl = fmt.Sprintf("%x", h.Sum(nil))
			messages = append(messages, m)
			blankline = 0
		} else if strings.Index(nextline, "From ") == 0 && len(line) == 1 {
			// New message coming up on next read
			blankline = 1
			i++
		} else {
			// Add lines to current message body
			messages[i].body = append(messages[i].body, line)
			messages[i].size += len(line)
		}
	}
	clientMessage = fmt.Sprintf("+OK Welcome %s. %d messages loaded.", user, len(messages))
	return
}