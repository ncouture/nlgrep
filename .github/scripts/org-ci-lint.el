(require 'org)

(setq org-ci/lint-failed nil)
(setq org-ci/fail-on-lint
      (not (string= (or (getenv "ORG_CI_FAIL_ON_LINT") "true") "false")))

(dolist (file command-line-args-left)
  (let ((buffer (find-file-noselect file)))
    (unwind-protect
        (with-current-buffer buffer
          (org-mode)
          (untabify (point-min) (point-max))
          (delete-trailing-whitespace)
          (goto-char (point-min))
          (while (re-search-forward "^\\([ \t]+\\)\\(#\\+\\)" nil t)
            (replace-match "\\2"))
          (org-table-map-tables #'org-table-align)
          (save-buffer)
          (let ((issues (org-lint)))
            (when (and (listp issues) issues)
              (setq org-ci/lint-failed t)
              (princ
               (format "\nOrg lint findings for %s:\n%s\n"
                       file
                       (mapconcat #'prin1-to-string issues "\n"))))))
      (when (buffer-live-p buffer)
        (kill-buffer buffer)))))

(when org-ci/lint-failed
  (when org-ci/fail-on-lint
    (kill-emacs 1)))
