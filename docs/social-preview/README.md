# Social preview

`social-preview.png` (2560x1280, a 2:1 image) is the repository's social
preview card - the image GitHub shows when the repo link is shared. It is
applied manually: repo Settings -> Social preview -> upload. GitHub has no
API for this setting.

`card.html` is the source. The card is laid out at 1280x640 and scaled 2x
in CSS, so a screenshot of the `#shot` element at CSS-pixel scale produces
the 2560x1280 PNG. To regenerate after editing, open the file in a browser
and capture that element (any full-page screenshot tool that respects
element bounds works). The palette matches the dark variants of the README
diagrams in `../diagrams/`.
