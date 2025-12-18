"""Technology Detection and Fingerprinting Module."""

import re
from typing import Dict, Any, List, Optional, Set
import aiohttp
from bs4 import BeautifulSoup
import mmh3
import hashlib

from .base import BaseModule


class TechDetectModule(BaseModule):
    """
    Module for deep technology fingerprinting and detection.
    
    Detects:
    - Web servers (nginx, Apache, IIS, etc.)
    - Programming languages (PHP, Java, Node.js, Python, Ruby, etc.)
    - Frameworks (Laravel, Django, Spring, Rails, Next.js, React, Vue)
    - CMS (WordPress, Drupal, Joomla, etc.)
    - Analytics (GA, GTM, Mixpanel, Segment)
    - Payment gateways
    - CDN & WAF
    - JS libraries
    - Third-party services
    - E-commerce platforms
    - Hosting providers
    """
    
    name = "tech_detect"
    description = "Technology fingerprinting and detection"
    is_active = False
    
    TECH_SIGNATURES = {
        "web_servers": {
            "nginx": {"headers": ["server:nginx"], "patterns": [], "confidence": 95},
            "Apache": {"headers": ["server:apache"], "patterns": [], "confidence": 95},
            "Apache Tomcat": {"headers": ["server:apache-coyote", "server:apache tomcat"], "patterns": [r"tomcat"], "confidence": 90},
            "IIS": {"headers": ["server:microsoft-iis"], "patterns": [], "confidence": 95},
            "LiteSpeed": {"headers": ["server:litespeed"], "patterns": [], "confidence": 95},
            "Caddy": {"headers": ["server:caddy"], "patterns": [], "confidence": 95},
            "OpenResty": {"headers": ["server:openresty"], "patterns": [], "confidence": 95},
            "gunicorn": {"headers": ["server:gunicorn"], "patterns": [], "confidence": 95},
            "uvicorn": {"headers": ["server:uvicorn"], "patterns": [], "confidence": 95},
            "Kestrel": {"headers": ["server:kestrel"], "patterns": [], "confidence": 90},
            "Cowboy": {"headers": ["server:cowboy"], "patterns": [], "confidence": 90},
            "Tengine": {"headers": ["server:tengine"], "patterns": [], "confidence": 90},
            "Jetty": {"headers": ["server:jetty"], "patterns": [], "confidence": 90},
            "Phusion Passenger": {"headers": ["server:phusion passenger"], "patterns": [], "confidence": 90},
        },
        "languages": {
            "PHP": {
                "headers": ["x-powered-by:php"],
                "patterns": [r"\.php(?:\?|$)", r"PHPSESSID"],
                "cookies": ["PHPSESSID"],
                "confidence": 90
            },
            "ASP.NET": {
                "headers": ["x-powered-by:asp.net", "x-aspnet-version", "x-aspnetmvc-version"],
                "patterns": [r"\.aspx", r"\.ashx", r"\.asmx", r"__VIEWSTATE", r"__EVENTVALIDATION"],
                "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
                "confidence": 95
            },
            "Java": {
                "headers": ["x-powered-by:servlet", "x-powered-by:jsp"],
                "patterns": [r"\.jsp", r"\.jsf", r"\.do", r"jsessionid", r"j_spring_security"],
                "cookies": ["JSESSIONID"],
                "confidence": 85
            },
            "Python": {
                "headers": ["x-powered-by:python", "server:python", "server:werkzeug"],
                "patterns": [r"csrfmiddlewaretoken", r"django", r"flask"],
                "confidence": 80
            },
            "Ruby": {
                "headers": ["x-powered-by:phusion", "x-runtime", "x-request-id"],
                "patterns": [r"\.rb", r"ruby"],
                "cookies": ["_session_id"],
                "confidence": 80
            },
            "Node.js": {
                "headers": ["x-powered-by:express", "x-powered-by:next.js"],
                "patterns": [r"node_modules", r"express"],
                "confidence": 85
            },
            "Go": {
                "headers": ["server:fasthttp"],
                "patterns": [r"go\.mod"],
                "confidence": 70
            },
            "Rust": {
                "headers": ["server:actix-web", "server:hyper", "server:rocket"],
                "patterns": [],
                "confidence": 85
            },
            "Elixir/Phoenix": {
                "headers": ["x-request-id"],
                "patterns": [r"phoenix", r"_csrf_token"],
                "cookies": ["_key"],
                "confidence": 75
            },
            "Perl": {
                "headers": ["x-powered-by:perl"],
                "patterns": [r"\.pl", r"\.cgi"],
                "confidence": 80
            },
            "ColdFusion": {
                "headers": ["x-powered-by:coldfusion"],
                "patterns": [r"\.cfm", r"\.cfc"],
                "cookies": ["CFID", "CFTOKEN"],
                "confidence": 90
            },
        },
        "frameworks": {
            "Laravel": {
                "patterns": [r"laravel_session", r"XSRF-TOKEN", r"laravel"],
                "cookies": ["laravel_session", "XSRF-TOKEN"],
                "confidence": 90
            },
            "Symfony": {
                "patterns": [r"symfony", r"sf-"],
                "cookies": ["PHPSESSID"],
                "confidence": 80
            },
            "CodeIgniter": {
                "patterns": [r"ci_session", r"codeigniter"],
                "cookies": ["ci_session"],
                "confidence": 85
            },
            "CakePHP": {
                "patterns": [r"cakephp"],
                "cookies": ["CAKEPHP"],
                "confidence": 85
            },
            "Django": {
                "patterns": [r"csrfmiddlewaretoken", r"django", r"__admin__"],
                "cookies": ["csrftoken", "sessionid"],
                "confidence": 90
            },
            "Flask": {
                "patterns": [r"werkzeug"],
                "cookies": ["session"],
                "headers": ["server:werkzeug"],
                "confidence": 75
            },
            "FastAPI": {
                "headers": ["server:uvicorn"],
                "patterns": [r"/docs", r"/openapi.json"],
                "confidence": 70
            },
            "Rails": {
                "patterns": [r"csrf-token", r"data-turbolinks", r"data-turbo", r"rails"],
                "cookies": ["_session"],
                "headers": ["x-runtime", "x-request-id"],
                "confidence": 85
            },
            "Spring": {
                "patterns": [r"_csrf", r"spring", r"j_spring"],
                "cookies": ["JSESSIONID"],
                "confidence": 80
            },
            "Spring Boot": {
                "patterns": [r"spring-boot", r"/actuator"],
                "headers": ["x-application-context"],
                "confidence": 85
            },
            "Express": {
                "headers": ["x-powered-by:express"],
                "patterns": [],
                "confidence": 90
            },
            "Koa": {
                "headers": ["x-powered-by:koa"],
                "patterns": [r"koa"],
                "confidence": 85
            },
            "Fastify": {
                "patterns": [r"fastify"],
                "confidence": 75
            },
            "NestJS": {
                "patterns": [r"nestjs", r"@nestjs"],
                "confidence": 80
            },
            "Next.js": {
                "patterns": [r"_next/static", r"__NEXT_DATA__", r"next/dist", r"/_next/"],
                "headers": ["x-nextjs-cache", "x-vercel-cache", "x-powered-by:next.js"],
                "confidence": 95
            },
            "Nuxt.js": {
                "patterns": [r"_nuxt/", r"__NUXT__", r"nuxt"],
                "confidence": 90
            },
            "Gatsby": {
                "patterns": [r"gatsby", r"/page-data/", r"gatsby-image"],
                "confidence": 90
            },
            "Remix": {
                "patterns": [r"remix", r"__remixContext"],
                "confidence": 85
            },
            "Astro": {
                "patterns": [r"astro", r"_astro/"],
                "confidence": 85
            },
            "SvelteKit": {
                "patterns": [r"sveltekit", r"__sveltekit"],
                "confidence": 85
            },
            "React": {
                "patterns": [r"react", r"_reactRootContainer", r"data-reactroot", r"react-dom", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
                "confidence": 85
            },
            "Vue.js": {
                "patterns": [r"vue", r"data-v-[a-f0-9]", r"Vue\.", r"__vue__"],
                "confidence": 85
            },
            "Angular": {
                "patterns": [r"ng-version", r"ng-app", r"angular", r"\[ng-", r"ng-binding"],
                "confidence": 90
            },
            "Svelte": {
                "patterns": [r"svelte", r"__svelte"],
                "confidence": 85
            },
            "Ember.js": {
                "patterns": [r"ember", r"data-ember"],
                "confidence": 85
            },
            "Backbone.js": {
                "patterns": [r"backbone"],
                "confidence": 80
            },
            "Meteor": {
                "patterns": [r"meteor", r"__meteor_runtime_config__"],
                "confidence": 90
            },
            "Blazor": {
                "patterns": [r"_blazor", r"blazor.webassembly"],
                "confidence": 90
            },
            ".NET Core": {
                "headers": ["x-powered-by:asp.net core"],
                "patterns": [r"aspnetcore"],
                "confidence": 85
            },
        },
        "cms": {
            "WordPress": {
                "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress", r"/wp-admin/"],
                "meta": ["generator:wordpress"],
                "confidence": 95
            },
            "Drupal": {
                "patterns": [r"/sites/default/", r"Drupal\.settings", r"drupal", r"/core/misc/drupal"],
                "headers": ["x-drupal-cache", "x-generator:drupal"],
                "meta": ["generator:drupal"],
                "confidence": 95
            },
            "Joomla": {
                "patterns": [r"/components/com_", r"/modules/mod_", r"joomla", r"/administrator/"],
                "meta": ["generator:joomla"],
                "confidence": 95
            },
            "Magento": {
                "patterns": [r"/skin/frontend/", r"/js/mage/", r"Mage\.", r"magento", r"/static/version"],
                "cookies": ["frontend", "frontend_cid"],
                "confidence": 90
            },
            "Shopify": {
                "patterns": [r"cdn\.shopify\.com", r"shopify", r"myshopify\.com", r"Shopify\."],
                "headers": ["x-shopify-stage", "x-shopid"],
                "confidence": 95
            },
            "BigCommerce": {
                "patterns": [r"bigcommerce", r"stencil"],
                "headers": ["x-bc-"],
                "confidence": 90
            },
            "WooCommerce": {
                "patterns": [r"woocommerce", r"wc-", r"/wc-api/"],
                "confidence": 90
            },
            "PrestaShop": {
                "patterns": [r"prestashop", r"/modules/", r"/themes/"],
                "meta": ["generator:prestashop"],
                "confidence": 90
            },
            "OpenCart": {
                "patterns": [r"opencart", r"/catalog/view/"],
                "confidence": 85
            },
            "Wix": {
                "patterns": [r"wix\.com", r"wixstatic\.com", r"_wix_browser_sess", r"wixsite\.com"],
                "confidence": 95
            },
            "Squarespace": {
                "patterns": [r"squarespace", r"static\.squarespace\.com", r"sqsp\."],
                "confidence": 95
            },
            "Ghost": {
                "patterns": [r"ghost", r"/ghost/"],
                "meta": ["generator:ghost"],
                "confidence": 90
            },
            "Webflow": {
                "patterns": [r"webflow", r"assets\.website-files\.com", r"webflow\.io"],
                "confidence": 95
            },
            "Contentful": {
                "patterns": [r"contentful", r"ctfassets\.net"],
                "confidence": 90
            },
            "Strapi": {
                "patterns": [r"strapi", r"/api/"],
                "confidence": 75
            },
            "Sanity": {
                "patterns": [r"sanity\.io", r"sanity"],
                "confidence": 85
            },
            "Prismic": {
                "patterns": [r"prismic\.io", r"prismic"],
                "confidence": 85
            },
            "HubSpot CMS": {
                "patterns": [r"hubspot", r"hs-sites\.com"],
                "confidence": 90
            },
            "Typo3": {
                "patterns": [r"typo3", r"/typo3conf/"],
                "meta": ["generator:typo3"],
                "confidence": 90
            },
            "Umbraco": {
                "patterns": [r"umbraco"],
                "confidence": 85
            },
            "Kentico": {
                "patterns": [r"kentico"],
                "meta": ["generator:kentico"],
                "confidence": 90
            },
            "Sitecore": {
                "patterns": [r"sitecore", r"/sitecore/"],
                "confidence": 85
            },
            "AEM (Adobe Experience Manager)": {
                "patterns": [r"/content/dam/", r"/etc/designs/", r"cq-", r"adobeaemcloud"],
                "confidence": 85
            },
            "Confluence": {
                "patterns": [r"confluence", r"atlassian"],
                "meta": ["generator:confluence"],
                "confidence": 90
            },
            "MediaWiki": {
                "patterns": [r"mediawiki", r"/wiki/"],
                "meta": ["generator:mediawiki"],
                "confidence": 90
            },
        },
        "analytics": {
            "Google Analytics": {
                "patterns": [r"google-analytics\.com", r"gtag\(", r"ga\(", r"UA-\d+", r"G-[A-Z0-9]+", r"googletagmanager.*gtag"],
                "confidence": 95
            },
            "Google Analytics 4": {
                "patterns": [r"G-[A-Z0-9]+", r"gtag.*config.*G-"],
                "confidence": 90
            },
            "Google Tag Manager": {
                "patterns": [r"googletagmanager\.com", r"GTM-[A-Z0-9]+", r"gtm\.js"],
                "confidence": 95
            },
            "Facebook Pixel": {
                "patterns": [r"connect\.facebook\.net", r"fbq\(", r"facebook\.com/tr", r"fbevents\.js"],
                "confidence": 95
            },
            "Meta Pixel": {
                "patterns": [r"fbq\(", r"facebook\.com/tr"],
                "confidence": 90
            },
            "Mixpanel": {
                "patterns": [r"mixpanel\.com", r"mixpanel\."],
                "confidence": 90
            },
            "Segment": {
                "patterns": [r"segment\.com", r"analytics\.js", r"cdn\.segment\.com", r"analytics\.identify"],
                "confidence": 90
            },
            "Hotjar": {
                "patterns": [r"hotjar\.com", r"hj\(", r"static\.hotjar\.com"],
                "confidence": 95
            },
            "Heap": {
                "patterns": [r"heap\.io", r"heapanalytics", r"heap-"],
                "confidence": 90
            },
            "Amplitude": {
                "patterns": [r"amplitude\.com", r"amplitude\.", r"cdn\.amplitude\.com"],
                "confidence": 90
            },
            "Plausible": {
                "patterns": [r"plausible\.io"],
                "confidence": 95
            },
            "Matomo/Piwik": {
                "patterns": [r"matomo", r"piwik", r"_paq\.push"],
                "confidence": 90
            },
            "Clicky": {
                "patterns": [r"clicky\.com", r"clicky_site_ids"],
                "confidence": 90
            },
            "Mouseflow": {
                "patterns": [r"mouseflow\.com"],
                "confidence": 90
            },
            "FullStory": {
                "patterns": [r"fullstory\.com", r"fs\.js", r"FullStory"],
                "confidence": 90
            },
            "Lucky Orange": {
                "patterns": [r"luckyorange\.com"],
                "confidence": 90
            },
            "Crazy Egg": {
                "patterns": [r"crazyegg\.com"],
                "confidence": 90
            },
            "PostHog": {
                "patterns": [r"posthog\.com", r"posthog"],
                "confidence": 90
            },
            "Clarity (Microsoft)": {
                "patterns": [r"clarity\.ms"],
                "confidence": 95
            },
            "Adobe Analytics": {
                "patterns": [r"omniture", r"s_code", r"adobe.*analytics", r"adobedtm\.com"],
                "confidence": 90
            },
            "Kissmetrics": {
                "patterns": [r"kissmetrics\.com"],
                "confidence": 90
            },
        },
        "payment": {
            "Stripe": {
                "patterns": [r"stripe\.com", r"js\.stripe\.com", r"Stripe\(", r"stripe-js"],
                "confidence": 95
            },
            "PayPal": {
                "patterns": [r"paypal\.com", r"paypalobjects\.com", r"paypal-scripts"],
                "confidence": 95
            },
            "Square": {
                "patterns": [r"squareup\.com", r"square\.com", r"squarecdn"],
                "confidence": 90
            },
            "Braintree": {
                "patterns": [r"braintree", r"braintreegateway\.com", r"braintreepayments"],
                "confidence": 90
            },
            "Adyen": {
                "patterns": [r"adyen\.com", r"adyencheckout"],
                "confidence": 90
            },
            "Klarna": {
                "patterns": [r"klarna\.com", r"klarna"],
                "confidence": 90
            },
            "Affirm": {
                "patterns": [r"affirm\.com", r"affirm"],
                "confidence": 90
            },
            "Afterpay": {
                "patterns": [r"afterpay\.com", r"afterpay"],
                "confidence": 90
            },
            "Apple Pay": {
                "patterns": [r"apple-pay", r"applepay"],
                "confidence": 85
            },
            "Google Pay": {
                "patterns": [r"google-pay", r"googlepay", r"pay\.google\.com"],
                "confidence": 85
            },
            "Razorpay": {
                "patterns": [r"razorpay\.com", r"razorpay"],
                "confidence": 95
            },
            "Mollie": {
                "patterns": [r"mollie\.com"],
                "confidence": 90
            },
            "2Checkout": {
                "patterns": [r"2checkout\.com"],
                "confidence": 90
            },
            "Authorize.net": {
                "patterns": [r"authorize\.net"],
                "confidence": 90
            },
        },
        "cdn_waf": {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
                "patterns": [r"cloudflare", r"cdnjs\.cloudflare\.com"],
                "confidence": 95
            },
            "AWS CloudFront": {
                "headers": ["x-amz-cf-id", "x-amz-cf-pop", "via:.*cloudfront"],
                "patterns": [r"cloudfront\.net", r"d[a-z0-9]+\.cloudfront\.net"],
                "confidence": 95
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "x-akamai-request-id"],
                "patterns": [r"akamai", r"akamaitech\.net", r"akamaized\.net"],
                "confidence": 95
            },
            "Fastly": {
                "headers": ["x-served-by", "x-cache:.*fastly", "fastly-restarts"],
                "patterns": [r"fastly", r"fastly\.net"],
                "confidence": 95
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "patterns": [r"sucuri"],
                "confidence": 95
            },
            "Incapsula/Imperva": {
                "headers": ["x-iinfo", "x-cdn:imperva"],
                "patterns": [r"incapsula", r"imperva"],
                "confidence": 95
            },
            "KeyCDN": {
                "headers": ["x-edge-location", "server:keycdn"],
                "patterns": [r"keycdn"],
                "confidence": 90
            },
            "StackPath": {
                "headers": ["x-sp-"],
                "patterns": [r"stackpath", r"stackpathcdn"],
                "confidence": 90
            },
            "Varnish": {
                "headers": ["x-varnish", "via:.*varnish"],
                "patterns": [],
                "confidence": 90
            },
            "AWS WAF": {
                "headers": ["x-amzn-waf-"],
                "patterns": [],
                "confidence": 90
            },
            "Azure CDN": {
                "headers": ["x-azure-ref", "x-ms-ref"],
                "patterns": [r"azureedge\.net", r"azure"],
                "confidence": 90
            },
            "Google Cloud CDN": {
                "headers": ["via:.*google"],
                "patterns": [r"googleusercontent\.com"],
                "confidence": 85
            },
            "BunnyCDN": {
                "headers": ["server:bunnycdn"],
                "patterns": [r"bunnycdn", r"b-cdn\.net"],
                "confidence": 90
            },
            "Vercel": {
                "headers": ["x-vercel-id", "x-vercel-cache"],
                "patterns": [r"vercel\.app", r"vercel\.com"],
                "confidence": 95
            },
            "Netlify": {
                "headers": ["x-nf-request-id", "x-netlify-request-id"],
                "patterns": [r"netlify", r"netlify\.app"],
                "confidence": 95
            },
            "Render": {
                "headers": ["x-render-origin-server"],
                "patterns": [r"onrender\.com"],
                "confidence": 90
            },
            "Railway": {
                "patterns": [r"railway\.app"],
                "confidence": 90
            },
            "Fly.io": {
                "headers": ["fly-request-id"],
                "patterns": [r"fly\.dev"],
                "confidence": 90
            },
        },
        "js_libraries": {
            "jQuery": {"patterns": [r"jquery", r"jQuery", r"jquery\.min\.js"], "confidence": 95},
            "jQuery UI": {"patterns": [r"jquery-ui", r"jquery\.ui"], "confidence": 90},
            "Bootstrap": {"patterns": [r"bootstrap", r"bootstrap\.min"], "confidence": 90},
            "Tailwind CSS": {"patterns": [r"tailwind", r"tailwindcss"], "confidence": 90},
            "Bulma": {"patterns": [r"bulma\.css", r"bulma\.min"], "confidence": 90},
            "Foundation": {"patterns": [r"foundation\.css", r"foundation\.min"], "confidence": 90},
            "Material UI": {"patterns": [r"@mui", r"material-ui", r"MuiButton"], "confidence": 85},
            "Chakra UI": {"patterns": [r"chakra-ui", r"@chakra-ui"], "confidence": 85},
            "Ant Design": {"patterns": [r"antd", r"ant-design"], "confidence": 85},
            "Semantic UI": {"patterns": [r"semantic-ui", r"semantic\.min"], "confidence": 85},
            "Lodash": {"patterns": [r"lodash", r"_\."], "confidence": 85},
            "Underscore.js": {"patterns": [r"underscore\.js"], "confidence": 85},
            "Moment.js": {"patterns": [r"moment\.js", r"moment\.min\.js"], "confidence": 90},
            "Day.js": {"patterns": [r"dayjs", r"day\.js"], "confidence": 90},
            "date-fns": {"patterns": [r"date-fns"], "confidence": 85},
            "Axios": {"patterns": [r"axios"], "confidence": 85},
            "D3.js": {"patterns": [r"d3\.js", r"d3\.min\.js", r"d3\.v"], "confidence": 90},
            "Three.js": {"patterns": [r"three\.js", r"three\.min\.js"], "confidence": 90},
            "Chart.js": {"patterns": [r"chart\.js", r"Chart\."], "confidence": 90},
            "Highcharts": {"patterns": [r"highcharts"], "confidence": 90},
            "ApexCharts": {"patterns": [r"apexcharts"], "confidence": 90},
            "Socket.io": {"patterns": [r"socket\.io"], "confidence": 90},
            "Alpine.js": {"patterns": [r"alpinejs", r"x-data", r"@click"], "confidence": 85},
            "HTMX": {"patterns": [r"htmx", r"hx-get", r"hx-post", r"hx-trigger"], "confidence": 90},
            "Stimulus": {"patterns": [r"stimulus", r"data-controller"], "confidence": 85},
            "Turbo": {"patterns": [r"turbo", r"data-turbo"], "confidence": 85},
            "Anime.js": {"patterns": [r"anime\.js", r"anime\.min"], "confidence": 85},
            "GSAP": {"patterns": [r"gsap", r"TweenMax", r"TweenLite"], "confidence": 90},
            "AOS": {"patterns": [r"aos\.js", r"aos\.css", r"data-aos"], "confidence": 90},
            "Swiper": {"patterns": [r"swiper", r"swiper-container"], "confidence": 85},
            "Slick": {"patterns": [r"slick\.js", r"slick-carousel"], "confidence": 85},
            "Owl Carousel": {"patterns": [r"owl\.carousel"], "confidence": 85},
            "Lightbox": {"patterns": [r"lightbox"], "confidence": 80},
            "Fancybox": {"patterns": [r"fancybox"], "confidence": 85},
            "Prism.js": {"patterns": [r"prism\.js", r"prismjs"], "confidence": 90},
            "Highlight.js": {"patterns": [r"highlight\.js", r"hljs"], "confidence": 90},
            "marked": {"patterns": [r"marked\.js", r"marked\.min"], "confidence": 85},
            "TinyMCE": {"patterns": [r"tinymce"], "confidence": 90},
            "CKEditor": {"patterns": [r"ckeditor"], "confidence": 90},
            "Quill": {"patterns": [r"quill\.js", r"quill\.min"], "confidence": 90},
            "Leaflet": {"patterns": [r"leaflet\.js", r"leaflet\.css"], "confidence": 90},
            "Mapbox": {"patterns": [r"mapbox", r"mapbox-gl"], "confidence": 90},
            "Google Maps": {"patterns": [r"maps\.googleapis\.com", r"google\.maps"], "confidence": 95},
            "DataTables": {"patterns": [r"datatables", r"DataTable"], "confidence": 90},
            "Select2": {"patterns": [r"select2"], "confidence": 85},
            "Chosen": {"patterns": [r"chosen\.jquery"], "confidence": 85},
            "Dropzone": {"patterns": [r"dropzone\.js", r"dropzone\.min"], "confidence": 90},
            "Cleave.js": {"patterns": [r"cleave\.js"], "confidence": 85},
            "IMask": {"patterns": [r"imask\.js"], "confidence": 85},
            "Popper.js": {"patterns": [r"popper\.js", r"@popperjs"], "confidence": 85},
            "Tippy.js": {"patterns": [r"tippy\.js", r"tippy-bundle"], "confidence": 85},
            "Toastr": {"patterns": [r"toastr\.js", r"toastr\.min"], "confidence": 85},
            "SweetAlert": {"patterns": [r"sweetalert", r"swal\."], "confidence": 90},
            "Noty": {"patterns": [r"noty\.js"], "confidence": 85},
        },
        "services": {
            "reCAPTCHA": {"patterns": [r"recaptcha", r"google\.com/recaptcha", r"grecaptcha"], "confidence": 95},
            "hCaptcha": {"patterns": [r"hcaptcha", r"hcaptcha\.com"], "confidence": 95},
            "Turnstile": {"patterns": [r"turnstile", r"challenges\.cloudflare\.com"], "confidence": 90},
            "Cloudinary": {"patterns": [r"cloudinary\.com", r"res\.cloudinary\.com"], "confidence": 95},
            "Imgix": {"patterns": [r"imgix\.net"], "confidence": 95},
            "ImageKit": {"patterns": [r"imagekit\.io"], "confidence": 90},
            "Uploadcare": {"patterns": [r"uploadcare\.com"], "confidence": 90},
            "Sentry": {"patterns": [r"sentry\.io", r"sentry", r"@sentry"], "confidence": 90},
            "LogRocket": {"patterns": [r"logrocket\.com", r"logrocket"], "confidence": 90},
            "Datadog RUM": {"patterns": [r"datadog", r"dd-rum"], "confidence": 90},
            "New Relic": {"patterns": [r"newrelic", r"new-relic", r"nr-data\.net"], "confidence": 90},
            "Bugsnag": {"patterns": [r"bugsnag\.com", r"bugsnag"], "confidence": 90},
            "Rollbar": {"patterns": [r"rollbar\.com", r"rollbar"], "confidence": 90},
            "Intercom": {"patterns": [r"intercom", r"widget\.intercom\.io", r"intercomSettings"], "confidence": 95},
            "Zendesk": {"patterns": [r"zendesk", r"zdassets\.com", r"zopim"], "confidence": 95},
            "Freshdesk": {"patterns": [r"freshdesk", r"freshchat"], "confidence": 90},
            "Drift": {"patterns": [r"drift\.com", r"driftt\.com"], "confidence": 90},
            "Crisp": {"patterns": [r"crisp\.chat", r"crisp\.im"], "confidence": 90},
            "Tawk.to": {"patterns": [r"tawk\.to", r"embed\.tawk\.to"], "confidence": 95},
            "LiveChat": {"patterns": [r"livechatinc\.com", r"livechat"], "confidence": 90},
            "Olark": {"patterns": [r"olark\.com", r"olark"], "confidence": 90},
            "Typeform": {"patterns": [r"typeform\.com"], "confidence": 95},
            "JotForm": {"patterns": [r"jotform\.com"], "confidence": 90},
            "Google Forms": {"patterns": [r"docs\.google\.com/forms"], "confidence": 95},
            "Formspree": {"patterns": [r"formspree\.io"], "confidence": 90},
            "Netlify Forms": {"patterns": [r"netlify", r"data-netlify"], "confidence": 85},
            "Mailchimp": {"patterns": [r"mailchimp", r"chimpstatic\.com", r"list-manage\.com"], "confidence": 95},
            "ConvertKit": {"patterns": [r"convertkit\.com"], "confidence": 90},
            "Klaviyo": {"patterns": [r"klaviyo\.com", r"klaviyo"], "confidence": 90},
            "ActiveCampaign": {"patterns": [r"activecampaign\.com"], "confidence": 90},
            "HubSpot": {"patterns": [r"hubspot", r"hs-scripts\.com", r"hs-banner\.com", r"hubapi\.com"], "confidence": 95},
            "Salesforce": {"patterns": [r"salesforce", r"force\.com", r"sfdc"], "confidence": 90},
            "Marketo": {"patterns": [r"marketo\.com", r"munchkin"], "confidence": 90},
            "Pardot": {"patterns": [r"pardot\.com", r"pi\.pardot\.com"], "confidence": 90},
            "Optimizely": {"patterns": [r"optimizely\.com", r"optimizely"], "confidence": 90},
            "VWO": {"patterns": [r"visualwebsiteoptimizer\.com", r"vwo"], "confidence": 90},
            "LaunchDarkly": {"patterns": [r"launchdarkly\.com", r"launchdarkly"], "confidence": 90},
            "Split.io": {"patterns": [r"split\.io"], "confidence": 90},
            "Auth0": {"patterns": [r"auth0\.com", r"auth0"], "confidence": 95},
            "Okta": {"patterns": [r"okta\.com", r"okta"], "confidence": 90},
            "Firebase": {"patterns": [r"firebase", r"firebaseapp\.com", r"firebaseio\.com"], "confidence": 95},
            "Supabase": {"patterns": [r"supabase\.com", r"supabase"], "confidence": 90},
            "AWS Amplify": {"patterns": [r"amplify", r"aws-amplify"], "confidence": 85},
            "Algolia": {"patterns": [r"algolia", r"algolianet\.com"], "confidence": 95},
            "Elasticsearch": {"patterns": [r"elasticsearch"], "confidence": 85},
            "Meilisearch": {"patterns": [r"meilisearch"], "confidence": 85},
            "Twilio": {"patterns": [r"twilio\.com", r"twilio"], "confidence": 90},
            "SendGrid": {"patterns": [r"sendgrid\.com", r"sendgrid"], "confidence": 90},
            "Mailgun": {"patterns": [r"mailgun\.com", r"mailgun"], "confidence": 90},
            "Amazon SES": {"patterns": [r"amazonses\.com"], "confidence": 85},
            "Pusher": {"patterns": [r"pusher\.com", r"pusher"], "confidence": 90},
            "Ably": {"patterns": [r"ably\.io", r"ably\.com"], "confidence": 90},
            "Socket.io": {"patterns": [r"socket\.io"], "confidence": 90},
            "OneSignal": {"patterns": [r"onesignal\.com", r"onesignal"], "confidence": 95},
            "PushEngage": {"patterns": [r"pushengage\.com"], "confidence": 90},
            "Disqus": {"patterns": [r"disqus\.com", r"disqus"], "confidence": 95},
            "Commento": {"patterns": [r"commento\.io"], "confidence": 90},
            "YouTube": {"patterns": [r"youtube\.com/embed", r"youtube-nocookie\.com", r"ytimg\.com"], "confidence": 95},
            "Vimeo": {"patterns": [r"vimeo\.com", r"player\.vimeo\.com"], "confidence": 95},
            "Wistia": {"patterns": [r"wistia\.com", r"wistia"], "confidence": 90},
            "Vidyard": {"patterns": [r"vidyard\.com"], "confidence": 90},
            "Calendly": {"patterns": [r"calendly\.com", r"calendly"], "confidence": 95},
            "Acuity Scheduling": {"patterns": [r"acuityscheduling\.com"], "confidence": 90},
            "Cookiebot": {"patterns": [r"cookiebot\.com", r"Cookiebot"], "confidence": 95},
            "OneTrust": {"patterns": [r"onetrust\.com", r"optanon"], "confidence": 95},
            "TrustArc": {"patterns": [r"trustarc\.com"], "confidence": 90},
            "Cookie Consent": {"patterns": [r"cookieconsent", r"cookie-consent"], "confidence": 85},
            "GDPR Cookie": {"patterns": [r"gdpr", r"cookie-notice"], "confidence": 70},
        },
        "hosting": {
            "AWS": {"patterns": [r"amazonaws\.com", r"aws\.amazon\.com", r"\.aws"], "confidence": 90},
            "Google Cloud": {"patterns": [r"googleapis\.com", r"google\.cloud", r"appspot\.com"], "confidence": 90},
            "Microsoft Azure": {"patterns": [r"azure\.com", r"azurewebsites\.net", r"\.azure\."], "confidence": 90},
            "DigitalOcean": {"patterns": [r"digitalocean", r"digitaloceanspaces\.com"], "confidence": 90},
            "Heroku": {"patterns": [r"herokuapp\.com", r"heroku"], "confidence": 95},
            "Vercel": {"patterns": [r"vercel\.app", r"now\.sh"], "confidence": 95},
            "Netlify": {"patterns": [r"netlify\.app", r"netlify\.com"], "confidence": 95},
            "GitHub Pages": {"patterns": [r"github\.io", r"githubusercontent\.com"], "confidence": 95},
            "GitLab Pages": {"patterns": [r"gitlab\.io"], "confidence": 95},
            "Render": {"patterns": [r"onrender\.com", r"render\.com"], "confidence": 95},
            "Railway": {"patterns": [r"railway\.app"], "confidence": 95},
            "Fly.io": {"patterns": [r"fly\.dev", r"fly\.io"], "confidence": 95},
            "Linode": {"patterns": [r"linode\.com", r"linodeobjects\.com"], "confidence": 90},
            "Vultr": {"patterns": [r"vultr\.com"], "confidence": 90},
            "Hetzner": {"patterns": [r"hetzner\.com", r"your-server\.de"], "confidence": 90},
            "OVH": {"patterns": [r"ovh\.com", r"ovhcloud\.com"], "confidence": 90},
            "Bluehost": {"patterns": [r"bluehost\.com"], "confidence": 90},
            "GoDaddy": {"patterns": [r"godaddy\.com", r"secureserver\.net"], "confidence": 90},
            "SiteGround": {"patterns": [r"siteground\.com", r"sgvps\.net"], "confidence": 90},
            "WP Engine": {"patterns": [r"wpengine\.com", r"wpenginepowered\.com"], "confidence": 95},
            "Kinsta": {"patterns": [r"kinsta\.cloud", r"kinsta\.com"], "confidence": 95},
            "Pantheon": {"patterns": [r"pantheon\.io", r"pantheonsite\.io"], "confidence": 95},
            "Acquia": {"patterns": [r"acquia\.com", r"acquia-sites\.com"], "confidence": 90},
            "Platform.sh": {"patterns": [r"platform\.sh"], "confidence": 90},
        }
    }
    
    FAVICON_HASHES = {
        -1137974563: "HubSpot",
        81586312: "Shopify",
        -335242539: "WordPress",
        116323821: "AWS",
        -247388890: "DigitalOcean",
        708578229: "Atlassian",
        1279544239: "GitHub",
        -130950122: "Microsoft",
        -1402875757: "Google",
        988422585: "Cloudflare",
        -1506307016: "nginx",
        -134051252: "Apache",
    }
    
    async def scan(
        self,
        url: str,
        session: Optional[aiohttp.ClientSession] = None
    ) -> Dict[str, Any]:
        """Perform technology detection scan."""
        self.logger.info(f"Scanning technologies for {url}")
        
        if session is None:
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(connector=connector)
            should_close = True
        else:
            should_close = False
        
        try:
            response = await self._make_request(session, url)
            
            if response is None:
                return self._create_result(
                    success=False,
                    error="Failed to fetch URL"
                )
            
            html_content = ""
            try:
                html_content = await response.text() if hasattr(response, 'text') else ""
            except:
                try:
                    html_content = response._body.decode('utf-8', errors='ignore') if hasattr(response, '_body') else ""
                except:
                    pass
            
            headers_dict = dict(response.headers)
            
            cookies = []
            if hasattr(response, 'cookies'):
                cookies = list(response.cookies.keys())
            
            favicon_hash = await self._get_favicon_hash(session, url)
            
            detected = await self._detect_technologies(
                html_content,
                headers_dict,
                cookies,
                url,
                favicon_hash
            )
            
            return self._create_result(
                success=True,
                data=detected
            )
            
        except Exception as e:
            self.logger.error(f"Error in tech detection: {e}")
            return self._create_result(success=False, error=str(e))
        finally:
            if should_close:
                await session.close()
    
    async def _get_favicon_hash(self, session: aiohttp.ClientSession, url: str) -> Optional[int]:
        """Get favicon mmh3 hash for identification."""
        try:
            from urllib.parse import urljoin
            favicon_url = urljoin(url, "/favicon.ico")
            
            async with session.get(favicon_url, timeout=10, ssl=False) as response:
                if response.status == 200:
                    content = await response.read()
                    if content:
                        import base64
                        b64 = base64.b64encode(content).decode()
                        return mmh3.hash(b64)
        except:
            pass
        return None
    
    async def _detect_technologies(
        self,
        html: str,
        headers: Dict[str, str],
        cookies: List[str],
        url: str,
        favicon_hash: Optional[int] = None
    ) -> Dict[str, Any]:
        """Detect all technologies from content."""
        detected: Dict[str, List[Dict[str, Any]]] = {
            "web_servers": [],
            "languages": [],
            "frameworks": [],
            "cms": [],
            "analytics": [],
            "payment": [],
            "cdn_waf": [],
            "js_libraries": [],
            "services": [],
            "hosting": []
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        html_lower = html.lower()
        cookies_lower = [c.lower() for c in cookies]
        
        soup = BeautifulSoup(html, 'lxml')
        meta_tags = self._extract_meta_tags(soup)
        scripts = self._extract_script_sources(soup)
        links = self._extract_link_sources(soup)
        
        for category, technologies in self.TECH_SIGNATURES.items():
            for tech_name, signatures in technologies.items():
                match_info = self._check_technology(
                    signatures,
                    headers_lower,
                    html_lower,
                    cookies_lower,
                    meta_tags,
                    scripts,
                    links
                )
                if match_info["matched"]:
                    detected[category].append({
                        "name": tech_name,
                        "confidence": signatures.get("confidence", 80),
                        "evidence": match_info["evidence"][:100]
                    })
        
        if favicon_hash and favicon_hash in self.FAVICON_HASHES:
            tech_name = self.FAVICON_HASHES[favicon_hash]
            for category in detected:
                if not any(t["name"] == tech_name for t in detected[category]):
                    detected["services"].append({
                        "name": tech_name,
                        "confidence": 85,
                        "evidence": f"Favicon hash: {favicon_hash}"
                    })
                    break
        
        for category in detected:
            detected[category].sort(key=lambda x: x["confidence"], reverse=True)
        
        flat_result = {}
        for category, techs in detected.items():
            flat_result[category] = [t["name"] for t in techs]
        
        total = sum(len(v) for v in flat_result.values())
        flat_result["summary"] = {
            "total_detected": total,
            "categories_with_findings": [
                cat for cat, techs in flat_result.items() 
                if techs and cat != "summary"
            ],
            "detection_details": {
                cat: detected[cat] for cat in detected if detected[cat]
            }
        }
        
        return flat_result
    
    def _check_technology(
        self,
        signatures: Dict,
        headers: Dict[str, str],
        html: str,
        cookies: List[str],
        meta_tags: Dict[str, str],
        scripts: List[str],
        links: List[str]
    ) -> Dict[str, Any]:
        """Check if technology is present based on signatures."""
        for header_sig in signatures.get("headers", []):
            if ":" in header_sig:
                h_name, h_val = header_sig.split(":", 1)
                if h_name in headers and h_val in headers[h_name]:
                    return {"matched": True, "evidence": f"Header: {h_name}={headers[h_name]}"}
            elif header_sig in headers:
                return {"matched": True, "evidence": f"Header present: {header_sig}"}
        
        for pattern in signatures.get("patterns", []):
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return {"matched": True, "evidence": f"Pattern: {match.group(0)[:50]}"}
        
        for cookie_sig in signatures.get("cookies", []):
            if cookie_sig.lower() in cookies:
                return {"matched": True, "evidence": f"Cookie: {cookie_sig}"}
        
        for meta_sig in signatures.get("meta", []):
            if ":" in meta_sig:
                m_name, m_val = meta_sig.split(":", 1)
                if m_name in meta_tags and m_val.lower() in meta_tags[m_name].lower():
                    return {"matched": True, "evidence": f"Meta: {m_name}={meta_tags[m_name][:50]}"}
        
        for pattern in signatures.get("patterns", []):
            for script in scripts:
                if re.search(pattern, script, re.IGNORECASE):
                    return {"matched": True, "evidence": f"Script: {script[:50]}"}
            for link in links:
                if re.search(pattern, link, re.IGNORECASE):
                    return {"matched": True, "evidence": f"Link: {link[:50]}"}
        
        return {"matched": False, "evidence": ""}
    
    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta tag values."""
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name", "") or tag.get("property", "")
            content = tag.get("content", "")
            if name and content:
                meta[name.lower()] = content
        return meta
    
    def _extract_script_sources(self, soup: BeautifulSoup) -> List[str]:
        """Extract script sources and inline content."""
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                scripts.append(src.lower())
            if script.string:
                scripts.append(script.string[:1000].lower())
        return scripts
    
    def _extract_link_sources(self, soup: BeautifulSoup) -> List[str]:
        """Extract link href values."""
        links = []
        for link in soup.find_all("link"):
            href = link.get("href", "")
            if href:
                links.append(href.lower())
        return links
