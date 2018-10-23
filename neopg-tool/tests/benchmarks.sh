bench  'dd if=/dev/urandom bs=4M count=20 | src/neopg armor' 'dd if=/dev/urandom bs=4M count=20 | gpg2 --enarmor' --output report.html
bench 'dd if=/dev/urandom bs=4M count=50 | gpg2 --print-md SHA1' 'dd if=/dev/urandom bs=4M count=50 | src/neopg hash --algo SHA-1'

dd if=/dev/urandom bs=4M count=10 | src/neopg gpg2 --compress-algo zip --encrypt -r obama  | src/neopg gpg2 --decrypt > /dev/null
dd if=/dev/urandom bs=4M count=10 | src/neopg gpg2 --compress-algo zlib --encrypt -r obama  | src/neopg gpg2 --decrypt > /dev/null
dd if=/dev/urandom bs=4M count=10 | src/neopg gpg2 --compress-algo bzip2 --encrypt -r obama  | src/neopg gpg2 --decrypt > /dev/null
