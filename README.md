# forcemsaa
Enable msaa for your old linux opengl games, the way mesa devs unintended you to

# Usage
```
LD_PRELOAD=~/forcemsaa.so your_gaem
```
# Configure
```
nano ~/msaaconfig
```
# Build and install
```
git clone https://github.com/VladDoc/forcemsaa.git
cd forcemsaa
mkdir build && cd build
cmake ..
make
make install
```
