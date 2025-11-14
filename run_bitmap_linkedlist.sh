rm -rf build/
mkdir build
cd build
head -c 32 /dev/urandom | xxd -p > seed_file
cmake -S .. -B . -DCMAKE_C_FLAGS="-O3 -w -DJOURNAL -DBITMAP_LIST -DROW_THRESHOLD=11 -DBIT_VECTOR=1024"
make
# ./mumhors t k l r rt tests ./seed_file