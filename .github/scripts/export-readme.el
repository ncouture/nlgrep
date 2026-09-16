(require 'ox-md)

(let ((readme-org
       (expand-file-name "README.org"
                         (or (getenv "GITHUB_WORKSPACE") default-directory))))
  (if (file-exists-p readme-org)
      (let ((readme-buffer (find-file-noselect readme-org)))
        (unwind-protect
            (with-current-buffer readme-buffer
              (org-mode)
              (org-md-export-to-markdown))
          (when (buffer-live-p readme-buffer)
            (kill-buffer readme-buffer))))
    (princ "README.org not found; skipping export.\n")))
