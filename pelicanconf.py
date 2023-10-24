AUTHOR = 'rbct'
SITENAME = 'Blog'
SITEURL = ''
PATH = 'content'
TIMEZONE = 'Europe/Rome'
DEFAULT_LANG = 'en'

# Blogroll
LINKS = ()

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

DEFAULT_PAGINATION = 10

# Uncomment following line if you want document-relative URLs when developing
# RELATIVE_URLS = True

# conf. specific for pelican-hyde theme
COLOR_THEME = "0"
BIO = """Hi, I'm Robert Raducioiu. Currently working as a Cyber Security Consultant
in Italy, I'm interested in low-level hacking, motorcycles, and outdoor fun.
"""
PROFILE_IMAGE = "avatar.png"

# theme options
THEME = 'themes/'

# Feeds configuration
FEED_DOMAIN = SITEURL
# Feed generation is usually not desired when developing
# taken from https://jackdewinter.github.io/2019/10/23/fine-tuning-pelican-producing-rss-feeds/
FEED_MAX_ITEMS = 15
FEED_ALL_ATOM = 'feeds/all.atom.xml'
FEED_ALL_RSS = 'feeds/all.rss.xml'
CATEGORY_FEED_ATOM = 'feeds/{slug}.atom.xml'
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = 'feeds/{slug}.atom.xml'
AUTHOR_FEED_RSS = 'feeds/{slug}.rss.xml'
