package snowboxauth

import (
	"bufio"
	"fmt"
	"io"
	"crypto/md5"
	"os"
	"regexp"
	"strings"
)

/* User authentication */
func Login(authfile string, auth_method string, user string, pass string, digest string, apop_stamp string) (success bool) {
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
				if matches[2] == pass {
					// And even a matching password
					success = true
				}
			} else if auth_method == "APOP" {
				// apop_stamp + password must match given digest
				h := md5.New()
				io.WriteString(h, apop_stamp + matches[2])
				sysdigest := fmt.Sprintf("%x", h.Sum(nil))
				if sysdigest == digest {
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
