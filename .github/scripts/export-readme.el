(require 'ox-md)

(let ((readme-org
       (expand-file-name "README.org"
                         (or (getenv "GITHUB_WORKSPACE") default-directory))))
  (if (file-exists-p readme-org)
      (let ((readme-buffer (find-file-noselect readme-org)))
        (with-current-buffer readme-buffer
          (org-mode)
          (org-md-export-to-markdown))
        (kill-buffer readme-buffer))
    (princ "README.org not found; skipping export.\n")))
