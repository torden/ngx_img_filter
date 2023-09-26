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


# Example

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
