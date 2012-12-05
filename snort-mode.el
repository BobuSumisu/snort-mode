;;; snort-mode.el --- Major mode for editing Snort rules

;; Author: Øyvind Ingvaldsen <oyvind.ingvaldsen@gmail.com>
;; Edited: <2012-12-04 Tue>
;; Version: 1.0

;;; Todo:
;; - Remove word lists when regexp are created? (free memory)
;; - Does not support user created rule actions
;; - Variable modifiers
;; - Syntax table

;;; Commentary:

;; Here are some of the things which `snort-mode' lets you do:
;;
;; TODO: Add some examples.

;;; Code;

(defcustom snort-basic-offset 4 "Snort identation level.")

(defvar snort-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map "C-j" 'newline-and-indent)
    map)
  "Keymap for Snort major mode")


(defvar snort-actions
  '("alert" "log" "pass" "activate" "dynamic" "drop" "reject" "sdrop" "ruletype"
    "var" "portvar" "ipvar"))

(defvar snort-modifiers
  '("msg" "reference" "gid" "sid" "rev" "classtype" "priority" "metadata" "content" "http_encode"
    "uricontent" "urilen" "isdataat" "pcre" "pkt_data" "file_data" "base64_decode" "base64_data"
    "byte_test" "byte_jump" "byte_extract" "ftp_bounce" "pcre" "asn1" "cvs" "dce_iface" "dce_opnum"
    "dce_stub_data" "sip_method" "sip_stat_code" "sip_header" "sip_body" "gtp_type" "gtp_info"
    "gtp_version" "ssl_version" "ssl_state" "nocase" "rawbytes" "depth" "offset" "distance" "within"
    "http_client_body" "http_cookie" "http_raw_cookie" "http_header" "http_raw_header" "http_method"
    "http_uri" "http_raw_uri" "http_stat_code" "http_stat_msg" "fast_pattern" "fragoffset" "fragbits"
    "ttl" "tos" "id" "ipopts" "dsize" "flags" "flow" "flowbits" "seq" "ack" "window" "itype" "icode"
    "icmp_id" "icmp_seq" "rpc" "ip_proto" "sameip" "stream_reassemble" "stream_size"
    "logto" "session" "resp" "react" "tag" "activates" "activated_by" "replace" "detection_filter"
    "treshold")
  "Rule modifiers, basically everything that can have ":" behind
  it - and some without arguments")

(defvar snort-keywords
  '("tcp" "udp" "icmp" "ip" "hex" "dec" "oct" "string" "type" "output" "any" "engine" "soid" "service"
    "norm" "raw" "relative" "bytes" "big" "little" "align" "invalid-entry" "enable" "disable" "client" "server"
    "both" "either" "printable" "binary" "all" "session" "host" "packets" "seconds" "bytes" "src" "dst" "track"
    "by_src" "by_dst" "uri" "header" "cookie" "utf8" "double_encode" "non_ascii" "uencode" "bare_byte" "ascii"
    "iis_encode" "bitstring_overflow" "double_overflow" "oversize_length" "absolute_offset" "relative_offset"
    "rr" "eol" "nop" "ts" "sec" "esec" "lsrr" "lsrre" "ssrr" "satid" "to_client" "to_server" "from_client"
    "from_server" "established" "not_established" "stateless" "no_stream" "only_stream" "no_frag" "only_frag"
    "set" "setx" "unset" "toggle" "isset" "isnotset" "noalert" "limit" "treshold" "count" "str_offset" "str_depth"
    "tagged")
  "arguments to modifiers")

(defvar snort-actions-regexp (regexp-opt snort-actions 'words))
(defvar snort-modifiers-regexp (regexp-opt snort-modifiers 'words))
(defvar snort-keywords-regexp (regexp-opt snort-keywords 'words))
(defvar snort-comments-regexp "\\(^\\|\\s-\\)\\#.*")
(defvar snort-variables-regexp "\\(^\\| \\)\\$\\(\\sw\\|\\s_\\)+")

(defvar snort-beginning-of-rule-regexp (concat "^\\s-*" snort-actions-regexp))
(defvar snort-end-of-rule-regexp ".*)\\s-*$")
(defvar snort-multiline-regexp ".*\\\\\\s-*$")
(defvar snort-ruletype-regexp "\\(ruletype\\|{\\|}\\)")


(defvar snort-font-lock-keywords
  `(
    (,snort-keywords-regexp . font-lock-keyword-face)
    (,snort-comments-regexp . font-lock-comment-face)
    (,snort-actions-regexp . font-lock-constant-face)
    (,snort-modifiers-regexp . font-lock-function-name-face)
    (,snort-variables-regexp . font-lock-variable-name-face)
    ))

(defun snort-indent-line ()
  "Indent current line of Snort code."
  (interactive)
  (beginning-of-line)
  (if (or (snort-beginning-of-rulep)
          (snort-full-line-commentp)
          (snort-ruletypep))
      (indent-line-to 0)
    (indent-line-to snort-basic-offset)))

(defun snort-beginning-of-rulep ()
  "Test if the current line is start of a rule."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (looking-at snort-beginning-of-rule-regexp)))

(defun snort-end-of-rulep ()
  "Test if the current line is the end of a rule."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (looking-at snort-end-of-rule-regexp)))

(defun snort-full-line-commentp ()
  "Test if the current line is a full line comment"
  (interactive)
  (save-excursion
    (beginning-of-line)
    (looking-at "^\\s-*\\#.*")))

(defun snort-multiline-rulep ()
  "Test if the current line is part of a multiline rule."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (looking-at snort-multiline-regexp)))

(defun snort-ruletypep ()
  "Test if the current line is part of a ruletype defenition."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (looking-at "^\\s-*\\(ruletype\\|{\\|}\\)")))


(defun snort-next-rule (&optional n)
  "Move to the beginning of the next rule."
  (interactive "p")
  (end-of-line)
  (re-search-forward snort-beginning-of-rule-regexp nil 'noerror n)
  (beginning-of-line))

(defun snort-previous-rule (&optional n)
  "Move to the beginning of the previous rule."
  (interactive "p")
  (while (snort-multiline-rulep)
    (forward-line -1))
  (re-search-backward snort-beginning-of-rule-regexp nil 'noerror n))

(defun snort-create-config-for-current-file ()
  "Create a simple Snort-config for the current file"
  (interactive)
  (let ((file (file-name-nondirectory buffer-file-name)))
        (with-temp-file (concat file ".conf")
          (insert (format "include %s\nconfig logdir: .\n" file)))))

(defun snort-validate ()
  "Validate the syntax of the current Snort-file."
  (interactive)
  (with-current-buffer (get-buffer-create "*snort*")
    (erase-buffer)
    (insert "[snort-mode] Validating buffer\n")
    (let ((conf-file (concat (file-name-nondirectory buffer-file-name) ".conf")))
      (if (file-exists-p conf-file)
          (insert "[snort-mode] Using config file: " conf-file "\n")
        (insert "[snort-mode] Config file not found - creating simple config: "
                conf-file "\n")
        (snort-create-config-for-current-file))
      (insert "[snort-mode] Starting Snort\n")
      (call-process "snort" nil (current-buffer) nil
                    "-c" conf-file
                    "-T")
      (switch-to-buffer-other-window (current-buffer))
      (goto-char (point-max)))))

(defun snort-test-pcap (pcap-file)
  "Test rules against a PCAP."
  (interactive "fChoose PCAP-file: ")
  (with-current-buffer (get-buffer-create "*snort*")
    (erase-buffer)
    (insert "[snort-mode] Validating buffer\n")
    (let ((conf-file (concat (file-name-nondirectory buffer-file-name) ".conf")))
      (insert (format "[snort-mode] Using PCAP-file: %s\n" pcap-file))
      (if (file-exists-p conf-file)
        (insert "[snort-mode] Using config file: " conf-file "\n")
        (insert "[snort-mode] Config file not found - creating simple config: "
                conf-file "\n")
        (snort-create-config-for-current-file))
      (insert "[snort-mode] Starting Snort\n")
      (switch-to-buffer-other-window (current-buffer))
      (call-process "snort" nil (current-buffer) nil
                    "-c" conf-file
                    "-r" (expand-file-name pcap-file)
                    "-A" "console"
                    "-q")
      (goto-char (point-max)))))

(define-derived-mode snort-mode prog-mode
  "Snort" "A major mode for editing Snort rules."
  ;; (set-syntax-table snort-mode-syntax-table)
  (set (make-local-variable 'font-lock-defaults) '(snort-font-lock-keywords))
  (set (make-local-variable 'indent-line-function) 'snort-indent-line)
  (setq comment-start "#"))

(provide 'snort-mode)

;;; snort-mode.el ends here
