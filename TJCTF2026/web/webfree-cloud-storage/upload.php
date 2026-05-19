<?php
require 'vendor/autoload.php';

use Chumper\Zipper\Zipper;

$uploadDir = __DIR__ . '/uploads/';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!isset($_FILES['zipfile'])) {
        die("No file uploaded.");
    }

    $tmpName = $_FILES['zipfile']['tmp_name'];
    $fileName = basename($_FILES['zipfile']['name']);

    if (pathinfo($fileName, PATHINFO_EXTENSION) !== 'zip') {
        die("Only zip files allowed.");
    }

    $destination = $uploadDir . $fileName;

    if (!move_uploaded_file($tmpName, $destination)) {
        die("Upload failed.");
    }

    echo "<p>File uploaded. Extracting...</p>";

    $zipper = new Zipper(); 

    $zipper->make($destination)->extractTo($uploadDir);

    echo "<p>Extraction complete!</p>";
}
?>

<!DOCTYPE html>
<html>
<body>
<h2>Upload your ZIP file</h2>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="zipfile" required>
    <button type="submit">Upload</button>
</form>
</body>
</html>