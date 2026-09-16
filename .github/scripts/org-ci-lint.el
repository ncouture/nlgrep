(require 'org)

(setq org-ci/lint-failed nil)

(dolist (file command-line-args-left)
  (with-current-buffer (find-file-noselect file)
    (org-mode)
    (untabify (point-min) (point-max))
    (delete-trailing-whitespace)
    (goto-char (point-min))
    (while (re-search-forward "^\\([ \t]+\\)\\(#\\+\\)" nil t)
      (replace-match "\\2"))
    (goto-char (point-min))
    (while (re-search-forward "^\\(\\*+\\)\\([^* \n]\\)" nil t)
      (replace-match "\\1 \\2"))
    (org-table-map-tables #'org-table-align)
    (save-buffer)
    (let* ((issues (org-lint))
           (lint-output
            (cond
             ((and (listp issues) issues)
              (mapconcat (lambda (issue) (format "%S" issue)) issues "\n"))
             ((let ((lint-buffer (get-buffer "*Org Lint*")))
                (and lint-buffer
                     (> (with-current-buffer lint-buffer (buffer-size)) 0)))
              (prog1
                  (with-current-buffer "*Org Lint*" (buffer-string))
                (kill-buffer "*Org Lint*"))))))
      (when lint-output
        (setq org-ci/lint-failed t)
        (princ (format "\nOrg lint findings for %s:\n%s\n" file lint-output))))
    (kill-buffer)))

(when org-ci/lint-failed
  (kill-emacs 1))
