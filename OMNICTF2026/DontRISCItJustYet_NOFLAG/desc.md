## Dont RISC it just yet
* *Authors: bad0psec and acebond*
* Get the flag at `RV64VMv4.exe + 23cb`
* https://insideyourkernel.com/2025-12-19-risc-it-for-the-biscuit.html
## NOTES
* Players should use the attached dist zip and not the one from the blog post for this challenge
* `stdout` is not given on remote, unless it prints the flag in which case it is given
* Your exploit should be build agnostic, i.e not rely on any hardcoded offsets.
* Your exploit might be blocked by Windows Defender
