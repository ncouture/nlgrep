(require 'ox-md)

(let ((readme-org
       (expand-file-name "README.org"
                         (or (getenv "GITHUB_WORKSPACE") default-directory))))
  (if (file-exists-p readme-org)
      (with-current-buffer (find-file-noselect readme-org)
        (org-mode)
        (org-md-export-to-markdown)
        (kill-buffer))
    (princ "README.org not found; skipping export.\n")))
