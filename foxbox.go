/* foxbox (2.1) - a webmail service written in Go
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
	"fmt"
	"net/http"
	"kiza.eu/snowbox/maildrop"
	"kiza.eu/snowbox/snowboxauth"
)

var maildir = "/var/mail"

func main() {
	fmt.Println("Hello, foxbox!")
	messages, success, clientMessage, logMessage := maildrop.LoadMaildrop("kiza", "testfiles")
	_ = clientMessage
	_ = logMessage
	_ = messages
	if success == false {
		fmt.Println("kaboom")
		return
	}

	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	if snowboxauth.Login("devuser.auth", "PLAIN", "kiza", "kaboom", "", "") == true {
		fmt.Fprintf(w, "Worky\n")
	} else {
		fmt.Fprintf(w, "Keep out!\n")
	}
}