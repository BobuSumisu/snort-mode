;;; snort-mode.el --- Major mode for editing Snort rules

;; Author: Øyvind Ingvaldsen <oyvind.ingvaldsen@gmail.com>
;; Created: 2012-12-04
;; Edited: 2012-12-05
;; Version: 1.0
;; Keywords: snort
;; Repository: https://github.com/BobuSumisu/snort-mode

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Todo:
;; See README.org or https://github.com/BobuSumisu/snort-mode
;;
;; All contributions are welcomed warmly :)

;;; Commentary:
;; Here are some of the things which `snort-mode' lets you do:
;;
;; - Jump between rules with `snort-next-rule' and `snort-previous-rule'.
;; - Validate rule syntax with `snort-validate' 
;; - Test rules against a PCAP-file with `snort-test-pcap'
;;

;;; Change Log:
;; See https://github.com/BobuSumisu/snort-mode for a complete changelog.

;;; Code;

(defgroup snort nil
  "Major mode for editing Snort rules.")

(defcustom snort-basic-offset 4
  "Snort identation level."
  :type 'integer
  :group 'snort)

(defcustom snort-executable "/usr/sbin/snort"
  "Path to the Snort executable"
  :type 'string
  :group 'snort)

(defvar snort-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map "C-j" 'newline-and-indent)
    map)
  "Keymap for Snort major mode.")

(defvar snort-actions
  '("alert" "log" "pass" "activate" "dynamic" "drop" "reject" "sdrop" "ruletype"
    "var" "portvar" "ipvar")
  "Rule actions in Snort.")

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
  "Rule action modifiers in Snort.")

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
  "Snort keywords.")

(defvar snort-actions-regexp (regexp-opt snort-actions 'words))
(defvar snort-modifiers-regexp (regexp-opt snort-modifiers 'words))
(defvar snort-keywords-regexp (regexp-opt snort-keywords 'words))
(defvar snort-comments-regexp "\\(^\\|\\s-\\)\\#.*")
(defvar snort-variables-regexp "\\(^\\| \\)\\$\\(\\sw\\|\\s_\\)+")

(defvar snort-beginning-of-rule-regexp (concat "^\\s-*" snort-actions-regexp))
(defvar snort-end-of-rule-regexp ".*)\\s-*$")
(defvar snort-multiline-regexp ".*\\\\\\s-*$")
(defvar snort-ruletype-regexp "\\(ruletype\\|{\\|}\\)")
(defvar snort-full-line-comment-regexp "^\\s-*\\#.*")

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
  (if (or (snort-beginning-of-rule-p)
          (snort-full-line-comment-p)
          (snort-ruletype-p))
      (indent-line-to 0)
    (indent-line-to snort-basic-offset)))

(defmacro def-snort-rule-p (name regexp)
  `(defun ,name ()
     "Auto-generated for snort-mode"
     (interactive)
     (save-excursion
       (beginning-of-line)
       (looking-at ,regexp))))

(def-snort-rule-p snort-beginning-of-rule-p snort-beginning-of-rule-regexp)
(def-snort-rule-p snort-end-of-rule-p snort-end-of-rule-regexp)
(def-snort-rule-p snort-multiline-rule-p snort-multiline-regexp)
(def-snort-rule-p snort-full-line-comment-p snort-full-line-comment-regexp)
(def-snort-rule-p snort-ruletype-p snort-ruletype-regexp)

(defun snort-next-rule (&optional n)
  "Move to the beginning of the next rule."
  (interactive "p")
  (end-of-line)
  (re-search-forward snort-beginning-of-rule-regexp nil 'noerror n)
  (beginning-of-line))

(defun snort-previous-rule (&optional n)
  "Move to the beginning of the previous rule."
  (interactive "p")
  (while (snort-multiline-rule-p)
    (forward-line -1))
  (re-search-backward snort-beginning-of-rule-regexp nil 'noerror n))

(defun snort-create-simple-config ()
  "Create a simple Snort-config for the current file [if not exists]."
  (interactive)
  (let ((rule-file (file-name-nondirectory buffer-file-name)) 
        (conf-file (concat (file-name-nondirectory buffer-file-name) ".conf")))
    (if (not (file-exists-p conf-file))
        (with-temp-file conf-file
          (insert (format "include %s\nconfig logdir: .\n" rule-file))))
    conf-file))

(defun snort-call-with-args (arglist)
  "Call Snort with provided arguments and output to current buffer."
  (insert (combine-and-quote-strings arglist))
  (eval `(call-process ,snort-executable nil (current-buffer) nil 
                ,@arglist)))

(defun snort-validate ()
  "Validate the syntax of the current Snort-file."
  (interactive)
  (let ((conf-file (snort-create-simple-config)))
    (with-current-buffer (get-buffer-create "*snort*")
      (erase-buffer)
      (snort-call-with-args
       `("-c" ,conf-file "-T"))
      (switch-to-buffer-other-window (current-buffer))
      (goto-char (point-max)))))

(defun snort-test-pcap (pcap-file)
  "Test Snort rules against a PCAP-file."
  (interactive "fChoose PCAP-file: ")
  (let ((conf-file (snort-create-simple-config))
        (pcap-file (expand-file-name pcap-file)))
    (with-current-buffer (get-buffer-create "*snort*")
      (erase-buffer)
      (snort-call-with-args
       `("-c" ,conf-file "-r" ,pcap-file "-A" "console" "-q"))
      (switch-to-buffer-other-window (current-buffer))
      (goto-char (point-max)))))

;;;###autoload
(define-derived-mode snort-mode prog-mode
  "Snort" "A major mode for editing Snort rules."
  :group 'snort
  ;; (set-syntax-table snort-mode-syntax-table)
  (set (make-local-variable 'font-lock-defaults) '(snort-font-lock-keywords))
  (set (make-local-variable 'indent-line-function) 'snort-indent-line)
  (setq comment-start "#"))

(provide 'snort-mode)

;;; snort-mode.el ends here
