/* snowbox 2 (2.0.2) - a POP3 server written in Go
 *
 * Copyright 2013 Oliver Feiler <kiza@kcore.de>
 * https://snowbox.kcore.de/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 * <http://www.gnu.org/licenses/gpl-3.0.html>
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"flag"
	"io"
	"log"
	"log/syslog"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var version = "2.0.2"

/* Command line options parser. */
var configfile = flag.String("configfile", "/etc/snowbox/config", "Config file to load.")

// Default config values. Overwritten by loadConfig().
var listen_interface = "127.0.0.1:110"
var useSSL = false
var sslOnly = false
var listen_ssl = "127.0.0.1:995"
var ssl_key = "/etc/snowbox/snowbox.key"
var ssl_cert = "/etc/snowbox/snowbox.cert"
var authfile = "/etc/snowbox/user.auth"
var maildir = "/var/mail"
var maildir_gid = "mail"
var loglevel = 1
var logfacility = "syslog"

/* Represents one message inside the maildrop */
type Message struct {
	body []string
	deleted bool
	size int
	uidl string
}

/* Main function handles TCP connections and spawns servers. */
func main() {
	flag.Parse()
	loadConfig()

	if (loglevel >= 1) {
		log_str := fmt.Sprintf("Snowbox (v%s) startup.", version)
		logEvent(nil, log_str, 0)
	}

	var ch = make(chan net.Conn)

	if sslOnly != true {
		ln, err := net.Listen("tcp", listen_interface)
		if err != nil {
			fmt.Println("Someting broke:", err)
			return
		}
		go handleConnection(ln, ch)
	}

	if useSSL == true {
		cert, cert_err := tls.LoadX509KeyPair(ssl_cert, ssl_key)
		if cert_err != nil {
			fmt.Println("Could not load certificates: ", ssl_key, ssl_cert)
			return
		}
		config := &tls.Config{}
		config.Certificates = []tls.Certificate{cert}
		tls_ln, tls_err := tls.Listen("tcp", listen_ssl, config);
		if tls_err != nil {
			fmt.Println("Someting broke:", tls_err)
			return
		}
		go handleConnection(tls_ln, ch)
	}

	if (loglevel >= 1) {
		log_str := fmt.Sprintf("Snowbox (v%s) ready to handle connections.", version)
		logEvent(nil, log_str, 0)
	}

	for {
		conn := <-ch
		go pop3main(conn)
	}
}

func handleConnection(ln net.Listener, ch chan net.Conn) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Something else broke:", err)
			continue
		}
		ch <- conn
	}
}

/* POP3 main loop go routine. */
func pop3main(c net.Conn) {
	if loglevel >= 3 {
		logEvent(c, "Connection established.", 3)
	}
	defer c.Close()

	user := ""					// Logged in user name
	connectionState := "auth"	// State changes to transaction after successful login.
	var messages []Message
	var maildrop *os.File
	var success bool

	// Construct APOP string
	part_rand := rand.Int63n(89999)+10000
	part_time := time.Now().Unix()
	part_host, _ := os.Hostname()
	apop_stamp := fmt.Sprintf("<%d.%d@%s>", part_rand, part_time, part_host)
	sendClientReply(c, false, []string{"+OK POP3 server ready, I guess " + apop_stamp})

	for {
		cmd, args, err := readClientCommand(c)
		if err != nil {
			if loglevel >= 2 {
				logEvent(c, "readClientCommand failed", 2)
			}
			return
		}

		if connectionState == "auth" {
			switch cmd {
				case "CAPA":
					popCmdCapa(c, connectionState)
				case "USER":
					if len(user) == 0 && len(args) > 0 {
						user = args
						sendClientReply(c, false, []string{"+OK May I have your password please?"})
					} else {
						popCmdError(c, "I already know you.")
					}
				case "PASS":
					if len(user) > 0 && len(args) > 0 {
						pass := args
						// Only if user is set accept pass and login client.
						if login("PLAIN", user, pass, "", "") == true {
							connectionState = "transaction"
							messages, maildrop, success = loadMaildrop(c, user)

							// Automatically release all locks after the main function has returned. It's MAGIC!
							defer removeLocks(maildrop)
							defer maildrop.Close()

							if success == false {
								return
							}
							if loglevel >= 3 {
								logEvent(c, "Login (" + user + ") via PLAIN succeeded.", 3)
							}
						} else {
							if loglevel >= 1 {
								logEvent(c, "Login (" + user + ") via PLAIN failed.", 1)
							}
							popCmdError(c, "Login incorrect.")
							return
						}
					} else {
						popCmdError(c, "Polite people introduce themselves first!")
					}
				case "APOP":
					if len(user) == 0 && len(args) > 0 {
						parts := strings.SplitN(args, " ", 2)
						if len(parts) != 2 {
							popCmdError(c, "Login incorrect.")
							return
						}
						user = parts[0]
						digest := parts[1]
						if login("APOP", user, "", digest, apop_stamp) == true {
							connectionState = "transaction"
							messages, maildrop, success = loadMaildrop(c, user)

							// Automatically release all locks after the main function has returned
							defer removeLocks(maildrop)
							defer maildrop.Close()

							if success == false {
								return
							}
							if loglevel >= 3 {
								logEvent(c, "Login (" + user + ") via APOP succeeded.", 3)
							}
						} else {
							if loglevel >= 1 {
								logEvent(c, "Login (" + user + ") via APOP failed.", 1)
							}
							popCmdError(c, "Login incorrect.")
							return
						}
					} else {
						popCmdError(c, "Too late to change your mind, stick with plain login!")
					}
				case "AUTH":
					popCmdAuth(c)
				case "QUIT":
					popCmdQuit(c, connectionState, "", messages, maildrop)
					return
				default:
					popCmdError(c, "")
			}
		} else if connectionState == "transaction" {
			switch cmd {
				case "CAPA":
					popCmdCapa(c, connectionState)
				case "DELE":
					if len(args) > 0 {
						msg, _ := strconv.Atoi(args)
						popCmdDele(c, messages, msg)
					} else {
						popCmdError(c, "")
					}
				case "LIST":
					if len(args) > 0 {
						msg, _ := strconv.Atoi(args)
						if err == nil {
							popCmdUidlAndList(c, messages, msg, "LIST", false)
						} else {
							popCmdError(c, "")
						}
					} else {
						popCmdUidlAndList(c, messages, 0, "LIST", true)
					}
				case "NOOP":
					popCmdNoop(c)
				case "QUIT":
					popCmdQuit(c, connectionState, user, messages, maildrop)
					connectionState = "update"	// superfluous
					return
				case "RETR":
					if len(args) > 0 {
						msg, err := strconv.Atoi(args)
						if err == nil {
							popCmdRetr(c, messages, msg)
						} else {
							popCmdError(c, "")
						}
					} else {
						popCmdError(c, "")
					}
				case "RSET":
					popCmdRset(c, messages)
				case "STAT":
					if len(args) > 0 {
						popCmdError(c, "")
					} else {
						popCmdStat(c, messages)
					}
				case "TOP":
					if len(args) > 0 {
						parts := strings.SplitN(args, " ", 2)
						if len(parts) != 2 {
							popCmdError(c, "")
							continue
						}
						msg, err := strconv.Atoi(parts[0])
						lines, err2 := strconv.Atoi(parts[1])
						if err == nil && err2 == nil {
							popCmdTop(c, messages, msg, lines)
						} else {
							popCmdError(c, "")
						}
					} else {
						popCmdError(c, "")
					}
				case "UIDL":
					if len(args) > 0 {
						msg, err := strconv.Atoi(args)
						if err == nil {
							popCmdUidlAndList(c, messages, msg, "UIDL", false)
						} else {
							popCmdError(c, "")
						}
					} else {
						popCmdUidlAndList(c, messages, 0, "UIDL", true)
					}
				default:
					popCmdError(c, "")
			}
		}
	}
}

/* Network wrapper functions. */
func readClientCommand(c net.Conn) (cmd string, args string, err error) {
	reader := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(2 * time.Minute)) // Set a timeout
	line, err := reader.ReadString('\n')
	c.SetDeadline(time.Time{}) //Reset timeout
	// Commands may be up to 255 chars (including CRLF) as per RFC2449
	if len(line) > 255 {
		return
	}
	line = strings.TrimRight(line, "\r\n")
	if err == nil {
		parts := strings.SplitN(line, " ", 2)
		cmd = strings.ToUpper(parts[0])
		args = ""
		if len(parts) == 2 {
			args = parts[1]
		}
	} else {
		if loglevel >= 2 {
			if e, ok := err.(net.Error); ok && e.Timeout() {
				logEvent(c, "Connection timed out.", 2)
			}

		}
		cmd = ""
	}
	return
}

/* Automatically send single and multi-line replies.
 * Client replies are automatically converted to end in CRLF
 * and the terminating character.
 */
func sendClientReply(c net.Conn, multiline bool, lines []string) {
	buf := new(bytes.Buffer)
	if multiline == false {
		// Single-line reply
		buf.WriteString(CRLFify(lines[0]))
	} else {
		// Multi-line reply
		for i := 0; i < len(lines); i++ {
			buf.WriteString(CRLFify(lines[i]))
		}
		// Reply must be terminated with .CRLF
		buf.WriteString(".\r\n")
	}
	
	count, err := buf.WriteTo(c)
	if err != nil {
		_ = count
		if loglevel >= 2 {
			logEvent(c, "Send to client failed.", 2)
		}
	}
}

/* Probably useless */
func remoteHostname(c net.Conn) (hostname string, hostport string) {
	hostaddr := c.RemoteAddr().String()
	hostip, hostport, err := net.SplitHostPort(hostaddr)
	if err != nil {
		hostname = hostip
		return
	}
	hostslice, err := net.LookupAddr(hostip)
	if err != nil {
		return
	} else {
		hostname = strings.TrimRight(hostslice[0], ".")
	}
	return
}

/* If a multine-line response has a line starting with '.'
 * it must be pre-padded with another dot.
 *
 * Single-line responses never start with a dot, so this
 * function can be universal.
 */
func CRLFify(data string) (prepared_data string) {
	// Remove any trailing LF from input. Mail lines read from the maildrop end in LF
	data = strings.TrimRight(data, "\n")
	if strings.Index(data, ".") == 0 {
		prepared_data = "." + data + "\r\n"
	} else {
		prepared_data = data + "\r\n"
	}
	return
}

/* User authentication */
func login(auth_method string, user string, pass string, digest string, apop_stamp string) (success bool) {
	success = false	// Assume not logged in
	file, err := os.Open(authfile)
	if err != nil {
		return
	}
	reader := bufio.NewReader(file)
	for {
		line, _ := reader.ReadString('\n')
		if line == "" {
			break
		}
		if strings.Index(line, "#") == 0 {
			// Skip comment
			continue
		}
		regex, _ := regexp.Compile("(.*?):\\s*(.*)")
		matches := regex.FindStringSubmatch(line)
		if len(matches) != 3 {
			// Match is only valid, if we have 3 parts
			continue
		}
		if matches[1] == user {
			// Found user entry
			if auth_method == "PLAIN" {
				if len(matches[2]) == len(pass) &&
					subtle.ConstantTimeCompare([]byte(matches[2]), []byte(pass)) == 1 {
					// And even a matching password
					success = true
				}
			} else if auth_method == "APOP" {
				// apop_stamp + password must match given digest
				h := md5.New()
				io.WriteString(h, apop_stamp + matches[2])
				sysdigest := fmt.Sprintf("%x", h.Sum(nil))
				if len(sysdigest) == len(digest) &&
					subtle.ConstantTimeCompare([]byte(sysdigest), []byte(digest)) == 1 {
					success = true
				}
			}
		}
	}
	if success == true {
		// We should now switch user ID
	}
	return
}

func loadMaildrop(c net.Conn, user string) (messages []Message, file *os.File, success bool) {
	success = true
	messages = make([]Message, 0, 100)
	maildrop := fmt.Sprintf("%s/%s", maildir, user)
	file, err := os.OpenFile(maildrop, syscall.O_RDWR | syscall.O_EXCL, 0660)
	if err != nil {
		sendClientReply(c, false, []string{"-ERR Could not load messages from mailbox. This is fatal. Self-destruct in 10..."})
		if loglevel >= 1 {
			log_str := fmt.Sprintf("Could not load mailbox for %s. Error: %s", user, err)
			logEvent(c, log_str, 1)
		}
		success = false
		return
	}
	// Lock user mailbox and disconnect if lock couldn't be acquired
	lockSuccess, lockMsg := acquireLocks(file)
	if lockSuccess == false {
		sendClientReply(c, false, []string{"-ERR Could not lock mailbox. Is another POP3 session active?"})
		if loglevel >= 2 {
			log_str := fmt.Sprintf("Could not lock mailbox for %s. (%s)", user, lockMsg)
			logEvent(c, log_str, 2)
		}
		success = false
		return
	}
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
	reply := fmt.Sprintf("+OK Welcome %s. %d messages loaded.", user, len(messages))
	sendClientReply(c, false, []string{reply})
	return
}

/* POP3 commands */
func popCmdAuth(c net.Conn) {
	// Somewhat violated RFC1734. Prints supported authorization mechanisms. In snowbox some clients refused to work without this cruft.
	lines := []string{"+OK These might work:", "APOP"}
	sendClientReply(c, true, lines)
}

func popCmdCapa(c net.Conn, connectionState string) {
	switch connectionState {
		case "auth":
			fallthrough
		case "transaction":
			sendClientReply(c, true, []string{"+OK You might try these", "USER", "UIDL", "EXPIRE NEVER", "PIPELINING", "TOP"})
		default:
			// It's dark in here! Where am I!?
	}
}

func popCmdDele(c net.Conn, messages []Message, message int) {
	num_messages := len(messages)
	if message > 0 && message <= num_messages {
		if messages[message-1].deleted == false {
			messages[message-1].deleted = true
			sendClientReply(c, false, []string{"+OK Message is gone."})
		} else {
			sendClientReply(c, false, []string{"-ERR Message already trashed."})
		}
	} else {
		sendClientReply(c, false, []string{"-ERR I don't have that message."})
	}
}


func popCmdNoop(c net.Conn) {
	sendClientReply(c, false, []string{"+OK ZZZzzz..."})
}

func popCmdQuit(c net.Conn, connectionState string, user string, messages []Message, file *os.File) {
	if connectionState == "auth" {
		// Never logged in. Just say bye and disconnect.
		sendClientReply(c, false, []string{"+OK Signing off."})
	} else if connectionState == "transaction" {
		// Write maildrop
		// If no messages were deleted at all we don't need to write the mbox.
		mailbox_changed := false
		for i:= 0; i < len(messages); i++ {
			if messages[i].deleted == true {
				mailbox_changed = true
			}
		}
		if mailbox_changed == true {
			n := 0
			file.Seek(0, 0)
			file.Truncate(0)
			for i:= 0; i < len(messages); i++ {
				if messages[i].deleted == false {	
					body := messages[i].body
					for j:= 0; j < len(body); j++ {
						_, err := file.WriteString(body[j])
						if err != nil {
							if loglevel >= 1 {
								log_str := fmt.Sprintf("Panic! Writing maildrop failed: %s", err)
								logEvent(c, log_str, 1)
							}
							return
						}
					}

					// Close mail with blank line
					_, err := file.WriteString("\n")
					if err != nil {
						if loglevel >= 1 {
							log_str := fmt.Sprintf("Panic! Writing maildrop failed: %s", err)
							logEvent(c, log_str, 1)
						}
						return
					}

					n++
				}
			}
			if loglevel >= 3 {
				log_str := fmt.Sprintf("Session for %s closed. %d messages written to maildrop.", user, n)
				logEvent(c, log_str, 3)
			}
		}
		// Locks are removed if thread exits
		sendClientReply(c, false, []string{"+OK Signing off. Trashing mailbox."})
	}
}

func popCmdRetr(c net.Conn, messages []Message, message int) {
	num_messages := len(messages)
	if message > 0 && message <= num_messages  {
		msg := messages[message-1]
		if msg.deleted == true {
			popCmdError(c, "Must have lost that message.")
			return
		}
		reply := make([]string, 0, len(msg.body)+1)
		reply = append(reply, "+OK")
		reply = append(reply, msg.body...)
		sendClientReply(c, true, reply)
	} else {
		popCmdError(c, "I don't have that message.")
	}
}

func popCmdRset(c net.Conn, messages []Message) {
	for i := 0; i < len(messages); i++ {
		messages[i].deleted = false
	}
	sendClientReply(c, false, []string{"+OK Rescued your messages."})
}

func popCmdStat(c net.Conn, messages []Message) {
	mbox_size := 0
	msg_count := 0
	for i := 0; i < len(messages); i++ {
		if messages[i].deleted == false {
			mbox_size += messages[i].size
			msg_count++
		}
	}
	reply := fmt.Sprintf("+OK %d %d", msg_count, mbox_size)
	sendClientReply(c, false, []string{reply})
}

func popCmdTop(c net.Conn, messages []Message, message int, lines int) {
	num_messages := len(messages)
	if message > 0 && message <= num_messages {
		msg := messages[message-1]
		if msg.deleted == true {
			popCmdError(c, "Must have lost that message.")
			return
		}
		reply := make([]string, 0, 1)
		reply = append(reply, "+OK")
		body := false
		count := 0
		for i := 0; i < len(msg.body); i++ {
			if strings.Index(msg.body[i], "\n") == 0 && body == false {
				body = true
			}
			reply = append(reply, msg.body[i])
			if body == true {
				count++
				if count > lines {
					break
				}
			}
		}
		sendClientReply(c, true, reply)
	} else {
		popCmdError(c, "I don't have that message.")
	}
}

func popCmdUidlAndList(c net.Conn, messages []Message, message int, cmd string, overview bool) {
	num_messages := len(messages)
	if overview == true {
		// Listing
		reply := make([]string, 0, num_messages+1)
		reply = append(reply, "+OK")
		for i := 0; i < num_messages; i++ {
			if messages[i].deleted == false {
				var line string
				if cmd == "UIDL" {
					line = fmt.Sprintf("%d %s", i+1, messages[i].uidl)
				} else if cmd == "LIST" {
					line = fmt.Sprintf("%d %d", i+1, messages[i].size)
				}
				reply = append(reply, line)
			}
		}
		sendClientReply(c, true, reply)
	} else if message > 0 {
		// Single message UIDL
		if message > num_messages || messages[message-1].deleted == true {
			popCmdError(c, "Must have lost that message.")
			return
		}
		var line string
		if cmd == "UIDL" {
			line = fmt.Sprintf("+OK %d %s", message, messages[message-1].uidl)
		} else if cmd == "LIST" {
			line = fmt.Sprintf("+OK %d %d", message, messages[message-1].size)
		}
		sendClientReply(c, false, []string{line})
	} else {
		popCmdError(c, "")
	}
}

/* Error reply, insult client. With optional bonus! */
func popCmdError(c net.Conn, error string) {
	if len(error) > 0 {
		errstr := "-ERR " + error
		sendClientReply(c, false, []string{errstr})
	} else {
		sendClientReply(c, false, []string{"-ERR Does not compute."})
	}
}

/* Syslog interface */
func logEvent(c net.Conn, str string, level int) {
	remoteAddr := ""
	log_str := ""
	if (c != nil) {
		remoteAddr = c.RemoteAddr().String()
		log_str = fmt.Sprintf("[connection from %s] %s", remoteAddr, str)
	} else {
		log_str = str
	}
	if logfacility == "stdout" {
		fmt.Println(log_str)
	} else if logfacility == "syslog" {
		syslog, _ := syslog.New(syslog.LOG_INFO, "snowbox")
		switch level {
			case 0:
				syslog.Info(log_str)
			case 1:
				syslog.Err(log_str)
			case 2:
				syslog.Warning(log_str)
			case 3:
				syslog.Debug(log_str)
			default:
		}
	}
}

/* Locking. Probably non-portable. */
func acquireLocks(file *os.File) (success bool, lockType string) {
	fd := int(file.Fd())
	success = true
	lockType = ""

	// flock()
	err := syscall.Flock(fd, syscall.LOCK_EX | syscall.LOCK_NB)
	if err != nil {
		lockType = fmt.Sprintf("flock: %s", err)
		success = false
	}

	// fcntl()
	k := struct {
		Type   uint32
		Whence uint32
		Start  uint64
		Len    uint64
		Pid    uint32
	}{
		Type:   syscall.F_WRLCK,
		Whence: uint32(os.SEEK_SET),
	}
	_, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_SETLK), uintptr(unsafe.Pointer(&k)))
	if errno != 0 {
		lockType = fmt.Sprintf("fcntl")
		success = false
	}
	return
}

// This function is automatically called via defer once main() has returned.
func removeLocks (file *os.File) {
	fd := int(file.Fd())

	// flock()
	syscall.Flock(fd, syscall.LOCK_UN)

	// fcntl
	k := struct {
		Type   uint32
		Whence uint32
		Start  uint64
		Len    uint64
		Pid    uint32
	}{
		Type:   syscall.F_UNLCK,
		Whence: uint32(os.SEEK_SET),
	}
	syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(syscall.F_SETLK), uintptr(unsafe.Pointer(&k)))
}

/* Update default configs from file. */
func loadConfig() {
	file, err := os.Open(*configfile)
	if err != nil {
		log.Fatal(err)
		return
	}
	reader := bufio.NewReader(file)
	for {
		line, _ := reader.ReadString('\n')
		if line == "" {
			break
		}
		if strings.Index(line, "#") == 0 {
			// Skip comment
			continue
		}
		regex, _ := regexp.Compile("(.*?):\\s*(.*)")
		matches := regex.FindStringSubmatch(line)
		if len(matches) != 3 {
			// Match is only valid, if we have 3 parts
			continue
		}
		switch matches[1] {
			case "listen":
				listen_interface = matches[2]
			case "use_ssl":
				if matches[2] == "no" {
					useSSL = false
				} else {
					useSSL = true
				}
			case "ssl_only":
				if matches[2] == "yes" {
					sslOnly = true
				} else {
					sslOnly = false
				}
			case "listen_ssl":
				listen_ssl = matches[2]
			case "ssl_key":
				ssl_key = matches[2]
			case "ssl_cert":
				ssl_cert = matches[2]
			case "authfile":
				authfile = matches[2]
			case "maildir":
				maildir = matches[2]
			case "maildir_gid":
				maildir_gid = matches[2]
			case "loglevel":
				val, err := strconv.ParseInt(matches[2], 0, 0)
				if err == nil {
					loglevel = int(val)
				} else {
					fmt.Println("Illegal config value for loglevel. Using default.", err)
				}
			case "logfacility":
				logfacility = matches[2]
			default:
				// nothing
		}
	}
}
