# ngx_img_filter

- Based on the ngx_image_filter

# Patch

- Fix : broken image when resizing trensparent png image

# New Features

- Output all images as webp
- Allow Quality options to work alone
- Add PNG Compress Level (=Quality) : 0 -> none, 1-9 -> level, -1 -> default


# Directives

|*Directive*|*Default*|*Context*|*Syntax*|
|--|--|--|--|
|img_filter_convert_webp|[on\|off]|location|img_filter_convert_webp on;|
|img_filter_convert_allow_only_quality|[on\|off]|location|img_filter_convert_allow_only_quality on;|
|img_filter_png_quality|-1|location|img_filter_png_quality 9;|


# Directives Example

```
img_filter resize                       $resize_width $resize_hegith;
img_filter_jpeg_quality                 $quality_jepg;
img_filter_webp_quality                 $quality_webp;
img_filter_buffer                       16M;
img_filter_transparency                 on;
img_filter_interlace                    off;
img_filter_convert_webp                 on;
img_filter_png_quality                  9;
img_filter_convert_allow_only_quality   on;
```


# Install (RockyLinux 8 or Higher)

```bash
# Install image libs
dnf install -y zlib \
zlib-devel \
zlib-static \
libpng \
libpng-devel \
libtiff \
libtiff-devel \
giflib \
giflib-devel \
libwebp \
libwebp-devel \
libvpx \
libvpx-devel \
curl \
libcurl-devel \
freetype-devel \
fontconfig-devel \
libXpm-devel \
libjpeg-turbo-devel \
openjpeg2-devel \
graphite2-devel \
libraqm-devel

# Install LIBIMAGQUANT
export VER_LIBIMGQUANT=2.18.0
wget https://github.com/ImageOptim/libimagequant/archive/refs/tags/${VER_LIBIMGQUANT}.tar.gz
tar xvzf ${VER_LIBIMGQUANT}.tar.gz
cd libimagequant-${VER_LIBIMGQUANT}
./configure --prefix=/usr/local/libimagequant --with-openmp=static
make -j4
make install
echo "/usr/local/libimagequant/lib" >> /etc/ld.so.conf
ldconfig

# Install libgd
export VER_LIBGD=2.3.3
wget https://github.com/libgd/libgd/releases/download/gd-${VER_LIBGD}/libgd-${VER_LIBGD}.tar.gz
tar xvzf libgd-${VER_LIBGD}.tar.gz
cd libgd-${VER_LIBGD}
./configure --prefix=/usr/local/libgd --with-liq=/usr/local/libimagequant
make -j4
make install
echo "/usr/local/libgd/lib" >> /etc/ld.so.conf
ldconfig

# Install Nginx
./configure --prefix=/usr/local/nginx --add-module=./ngx_img_filter
make
make install
```
