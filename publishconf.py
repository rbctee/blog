# This file is only used if you use `make publish` or
# explicitly specify it as your config file.

from pelicanconf import *
import os
import sys
sys.path.append(os.curdir)

# If your site is available via HTTPS, make sure SITEURL begins with https://
SITEURL = 'https://blog.rbct.it'
RELATIVE_URLS = False

DELETE_OUTPUT_DIRECTORY = True

# Social widget
SOCIAL = (
    ('linkedin', 'https://www.linkedin.com/in/rbct/'),
    ('github', 'https://github.com/rbctee'),
)
GITHUB_URL = 'http://github.com/rbctee/'
STATIC_PATHS = [
    'images',
    'extra',  # this
]
EXTRA_PATH_METADATA = {
    'extra/custom.css': {'path': 'custom.css'},
    'extra/robots.txt': {'path': 'robots.txt'},
    'extra/favicon.ico': {'path': 'favicon.ico'},  # and this
    'extra/CNAME': {'path': 'CNAME'},
    'extra/LICENSE': {'path': 'LICENSE'},
    'extra/README': {'path': 'README'},
}

# Feed Items
# taken from https://jackdewinter.github.io/2019/10/23/fine-tuning-pelican-producing-rss-feeds/
FEED_MAX_ITEMS = 15
FEED_ALL_ATOM = 'feeds/all.atom.xml'
CATEGORY_FEED_ATOM = 'feeds/{slug}.atom.xml'
