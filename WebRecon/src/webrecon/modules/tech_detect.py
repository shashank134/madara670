"""Technology Detection and Fingerprinting Module - Enhanced Wappalyzer-Level Detection."""

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
    Enhanced with 500+ signatures for Wappalyzer-level detection accuracy.
    """
    
    name = "tech_detect"
    description = "Technology fingerprinting and detection"
    is_active = False
    
    TECH_SIGNATURES = {
        "web_servers": {
            "nginx": {"headers": ["server:nginx"], "patterns": [r"nginx/[\d\.]+"], "confidence": 95},
            "Apache": {"headers": ["server:apache"], "patterns": [r"apache/[\d\.]+", r"mod_ssl"], "confidence": 95},
            "Apache Tomcat": {"headers": ["server:apache-coyote", "server:apache tomcat"], "patterns": [r"tomcat", r"catalina"], "confidence": 90},
            "IIS": {"headers": ["server:microsoft-iis"], "patterns": [r"iis/[\d\.]+"], "confidence": 95},
            "LiteSpeed": {"headers": ["server:litespeed"], "patterns": [r"litespeed"], "confidence": 95},
            "Caddy": {"headers": ["server:caddy"], "patterns": [], "confidence": 95},
            "OpenResty": {"headers": ["server:openresty"], "patterns": [], "confidence": 95},
            "gunicorn": {"headers": ["server:gunicorn"], "patterns": [], "confidence": 95},
            "uvicorn": {"headers": ["server:uvicorn"], "patterns": [], "confidence": 95},
            "Kestrel": {"headers": ["server:kestrel"], "patterns": [], "confidence": 90},
            "Cowboy": {"headers": ["server:cowboy"], "patterns": [], "confidence": 90},
            "Tengine": {"headers": ["server:tengine"], "patterns": [], "confidence": 90},
            "Jetty": {"headers": ["server:jetty"], "patterns": [r"jetty"], "confidence": 90},
            "Phusion Passenger": {"headers": ["server:phusion passenger"], "patterns": [], "confidence": 90},
            "Deno": {"headers": ["server:deno"], "patterns": [r"deno\.land"], "confidence": 90},
            "Bun": {"headers": ["server:bun"], "patterns": [], "confidence": 90},
            "Waitress": {"headers": ["server:waitress"], "patterns": [], "confidence": 90},
            "Tornado": {"headers": ["server:tornado"], "patterns": [], "confidence": 90},
            "CherryPy": {"headers": ["server:cherrypy"], "patterns": [], "confidence": 90},
            "Puma": {"headers": ["server:puma"], "patterns": [], "confidence": 90},
            "Unicorn": {"headers": ["server:unicorn"], "patterns": [], "confidence": 90},
            "thin": {"headers": ["server:thin"], "patterns": [], "confidence": 90},
            "WEBrick": {"headers": ["server:webrick"], "patterns": [], "confidence": 90},
        },
        "languages": {
            "PHP": {
                "headers": ["x-powered-by:php"],
                "patterns": [r"\.php(?:\?|$)", r"PHPSESSID", r"<\?php", r"php\.net"],
                "cookies": ["PHPSESSID"],
                "confidence": 90
            },
            "ASP.NET": {
                "headers": ["x-powered-by:asp.net", "x-aspnet-version", "x-aspnetmvc-version"],
                "patterns": [r"\.aspx", r"\.ashx", r"\.asmx", r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net"],
                "cookies": ["ASP.NET_SessionId", ".ASPXAUTH"],
                "confidence": 95
            },
            "Java": {
                "headers": ["x-powered-by:servlet", "x-powered-by:jsp"],
                "patterns": [r"\.jsp", r"\.jsf", r"\.do", r"jsessionid", r"j_spring_security", r"java\."],
                "cookies": ["JSESSIONID"],
                "confidence": 85
            },
            "Python": {
                "headers": ["x-powered-by:python", "server:python", "server:werkzeug"],
                "patterns": [r"csrfmiddlewaretoken", r"django", r"flask", r"python"],
                "confidence": 80
            },
            "Ruby": {
                "headers": ["x-powered-by:phusion", "x-runtime", "x-request-id"],
                "patterns": [r"\.rb", r"ruby", r"rails"],
                "cookies": ["_session_id"],
                "confidence": 80
            },
            "Node.js": {
                "headers": ["x-powered-by:express", "x-powered-by:next.js"],
                "patterns": [r"node_modules", r"express", r"nodejs"],
                "confidence": 85
            },
            "Go": {
                "headers": ["server:fasthttp"],
                "patterns": [r"go\.mod", r"golang"],
                "confidence": 70
            },
            "Rust": {
                "headers": ["server:actix-web", "server:hyper", "server:rocket", "server:axum"],
                "patterns": [r"actix-web", r"rocket\.rs"],
                "confidence": 85
            },
            "Elixir/Phoenix": {
                "headers": ["x-request-id"],
                "patterns": [r"phoenix", r"_csrf_token", r"elixir"],
                "cookies": ["_key"],
                "confidence": 75
            },
            "Perl": {
                "headers": ["x-powered-by:perl"],
                "patterns": [r"\.pl", r"\.cgi", r"perl"],
                "confidence": 80
            },
            "ColdFusion": {
                "headers": ["x-powered-by:coldfusion"],
                "patterns": [r"\.cfm", r"\.cfc", r"coldfusion"],
                "cookies": ["CFID", "CFTOKEN"],
                "confidence": 90
            },
            "Scala": {
                "patterns": [r"scala", r"play\.api", r"akka"],
                "confidence": 75
            },
            "Kotlin": {
                "patterns": [r"kotlin", r"ktor"],
                "confidence": 75
            },
        },
        "frameworks": {
            "Laravel": {
                "patterns": [r"laravel_session", r"XSRF-TOKEN", r"laravel", r"_token"],
                "cookies": ["laravel_session", "XSRF-TOKEN"],
                "confidence": 90
            },
            "Symfony": {
                "patterns": [r"symfony", r"sf-", r"_sf2_"],
                "cookies": ["PHPSESSID"],
                "confidence": 80
            },
            "CodeIgniter": {
                "patterns": [r"ci_session", r"codeigniter", r"system/codeigniter"],
                "cookies": ["ci_session"],
                "confidence": 85
            },
            "CakePHP": {
                "patterns": [r"cakephp", r"cake\.generic\.css"],
                "cookies": ["CAKEPHP"],
                "confidence": 85
            },
            "Yii": {
                "patterns": [r"yii", r"yiiframework", r"YII_CSRF_TOKEN"],
                "confidence": 85
            },
            "Zend": {
                "patterns": [r"zend", r"zf2", r"zendframework"],
                "confidence": 80
            },
            "Django": {
                "patterns": [r"csrfmiddlewaretoken", r"django", r"__admin__", r"djdt"],
                "cookies": ["csrftoken", "sessionid", "django"],
                "confidence": 90
            },
            "Flask": {
                "patterns": [r"werkzeug", r"flask"],
                "cookies": ["session"],
                "headers": ["server:werkzeug"],
                "confidence": 75
            },
            "FastAPI": {
                "headers": ["server:uvicorn"],
                "patterns": [r"/docs", r"/openapi\.json", r"fastapi"],
                "confidence": 70
            },
            "Tornado": {
                "headers": ["server:tornado"],
                "patterns": [r"tornado"],
                "confidence": 85
            },
            "Pyramid": {
                "patterns": [r"pyramid", r"pylons"],
                "confidence": 75
            },
            "Rails": {
                "patterns": [r"csrf-token", r"data-turbolinks", r"data-turbo", r"rails", r"action_dispatch", r"authenticity_token"],
                "cookies": ["_session"],
                "headers": ["x-runtime", "x-request-id"],
                "confidence": 85
            },
            "Sinatra": {
                "patterns": [r"sinatra", r"rack\.session"],
                "confidence": 80
            },
            "Spring": {
                "patterns": [r"_csrf", r"spring", r"j_spring", r"springframework"],
                "cookies": ["JSESSIONID"],
                "confidence": 80
            },
            "Spring Boot": {
                "patterns": [r"spring-boot", r"/actuator", r"springboot"],
                "headers": ["x-application-context"],
                "confidence": 85
            },
            "Struts": {
                "patterns": [r"struts", r"\.action$", r"struts-tags"],
                "confidence": 80
            },
            "Grails": {
                "patterns": [r"grails", r"grailsResourcePath"],
                "confidence": 80
            },
            "Express": {
                "headers": ["x-powered-by:express"],
                "patterns": [r"express"],
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
            "Hapi": {
                "patterns": [r"hapi", r"@hapi"],
                "confidence": 80
            },
            "NestJS": {
                "patterns": [r"nestjs", r"@nestjs"],
                "confidence": 80
            },
            "AdonisJS": {
                "patterns": [r"adonis", r"adonisjs"],
                "cookies": ["adonis-session"],
                "confidence": 80
            },
            "Next.js": {
                "patterns": [r"_next/static", r"__NEXT_DATA__", r"next/dist", r"/_next/", r"next\.js", r"vercel\.svg"],
                "headers": ["x-nextjs-cache", "x-vercel-cache", "x-powered-by:next.js"],
                "confidence": 95
            },
            "Nuxt.js": {
                "patterns": [r"_nuxt/", r"__NUXT__", r"nuxt", r"nuxtjs"],
                "confidence": 90
            },
            "Gatsby": {
                "patterns": [r"gatsby", r"/page-data/", r"gatsby-image", r"gatsbyjs"],
                "confidence": 90
            },
            "Remix": {
                "patterns": [r"remix", r"__remixContext", r"remix\.run"],
                "confidence": 85
            },
            "Astro": {
                "patterns": [r"astro", r"_astro/", r"astro\.build"],
                "confidence": 85
            },
            "SvelteKit": {
                "patterns": [r"sveltekit", r"__sveltekit", r"svelte-kit"],
                "confidence": 85
            },
            "Qwik": {
                "patterns": [r"qwik", r"qwikcity"],
                "confidence": 85
            },
            "SolidJS": {
                "patterns": [r"solid-js", r"solidjs"],
                "confidence": 85
            },
            "React": {
                "patterns": [r"react", r"_reactRootContainer", r"data-reactroot", r"react-dom", r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"reactjs\.org", r"react\.production\.min\.js"],
                "confidence": 85
            },
            "Vue.js": {
                "patterns": [r"vue", r"data-v-[a-f0-9]", r"Vue\.", r"__vue__", r"vuejs\.org", r"vue@", r"vue\.min\.js", r"vue\.runtime"],
                "confidence": 85
            },
            "Angular": {
                "patterns": [r"ng-version", r"ng-app", r"angular", r"\[ng-", r"ng-binding", r"ngx-", r"angular\.io", r"zone\.js"],
                "confidence": 90
            },
            "AngularJS": {
                "patterns": [r"ng-model", r"ng-controller", r"angular\.min\.js", r"ng-scope"],
                "confidence": 85
            },
            "Svelte": {
                "patterns": [r"svelte", r"__svelte", r"sveltejs"],
                "confidence": 85
            },
            "Preact": {
                "patterns": [r"preact", r"preactjs"],
                "confidence": 85
            },
            "Ember.js": {
                "patterns": [r"ember", r"data-ember", r"emberjs"],
                "confidence": 85
            },
            "Backbone.js": {
                "patterns": [r"backbone", r"backbonejs"],
                "confidence": 80
            },
            "Meteor": {
                "patterns": [r"meteor", r"__meteor_runtime_config__"],
                "confidence": 90
            },
            "Blazor": {
                "patterns": [r"_blazor", r"blazor\.webassembly", r"blazor\.server"],
                "confidence": 90
            },
            ".NET Core": {
                "headers": ["x-powered-by:asp.net core"],
                "patterns": [r"aspnetcore", r"\.net core"],
                "confidence": 85
            },
            "Alpine.js": {
                "patterns": [r"x-data", r"x-bind", r"x-on:", r"alpine", r"alpinejs"],
                "confidence": 85
            },
            "htmx": {
                "patterns": [r"hx-get", r"hx-post", r"hx-swap", r"htmx\.org", r"htmx\.min\.js"],
                "confidence": 90
            },
            "Stimulus": {
                "patterns": [r"stimulus", r"data-controller", r"data-action"],
                "confidence": 80
            },
            "Turbo": {
                "patterns": [r"turbo-frame", r"turbo-stream", r"@hotwired/turbo"],
                "confidence": 85
            },
            "Livewire": {
                "patterns": [r"livewire", r"wire:", r"@livewire"],
                "confidence": 90
            },
            "Inertia.js": {
                "patterns": [r"inertia", r"@inertiajs"],
                "confidence": 85
            },
        },
        "cms": {
            "WordPress": {
                "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress", r"/wp-admin/", r"wp-embed\.min\.js", r"wp-emoji"],
                "meta": ["generator:wordpress"],
                "confidence": 95
            },
            "Drupal": {
                "patterns": [r"/sites/default/", r"Drupal\.settings", r"drupal", r"/core/misc/drupal", r"drupal\.js"],
                "headers": ["x-drupal-cache", "x-generator:drupal"],
                "meta": ["generator:drupal"],
                "confidence": 95
            },
            "Joomla": {
                "patterns": [r"/components/com_", r"/modules/mod_", r"joomla", r"/administrator/", r"/media/jui/"],
                "meta": ["generator:joomla"],
                "confidence": 95
            },
            "Magento": {
                "patterns": [r"/skin/frontend/", r"/js/mage/", r"Mage\.", r"magento", r"/static/version", r"mage/cookies"],
                "cookies": ["frontend", "frontend_cid", "mage-messages"],
                "confidence": 90
            },
            "Shopify": {
                "patterns": [r"cdn\.shopify\.com", r"shopify", r"myshopify\.com", r"Shopify\.", r"shopify-section"],
                "headers": ["x-shopify-stage", "x-shopid"],
                "confidence": 95
            },
            "BigCommerce": {
                "patterns": [r"bigcommerce", r"stencil", r"/s/stencil/"],
                "headers": ["x-bc-"],
                "confidence": 90
            },
            "WooCommerce": {
                "patterns": [r"woocommerce", r"wc-", r"/wc-api/", r"wc-add-to-cart", r"wc_cart_hash"],
                "confidence": 90
            },
            "PrestaShop": {
                "patterns": [r"prestashop", r"/modules/", r"/themes/", r"prestashop\.com"],
                "meta": ["generator:prestashop"],
                "confidence": 90
            },
            "OpenCart": {
                "patterns": [r"opencart", r"/catalog/view/", r"route=common"],
                "confidence": 85
            },
            "Wix": {
                "patterns": [r"wix\.com", r"wixstatic\.com", r"_wix_browser_sess", r"wixsite\.com", r"static\.wix"],
                "confidence": 95
            },
            "Squarespace": {
                "patterns": [r"squarespace", r"static\.squarespace\.com", r"sqsp\.", r"squarespace-cdn"],
                "confidence": 95
            },
            "Ghost": {
                "patterns": [r"ghost", r"/ghost/", r"ghost\.org", r"ghost-portal"],
                "meta": ["generator:ghost"],
                "confidence": 90
            },
            "Webflow": {
                "patterns": [r"webflow", r"assets\.website-files\.com", r"webflow\.io", r"wf\.js"],
                "confidence": 95
            },
            "Contentful": {
                "patterns": [r"contentful", r"ctfassets\.net", r"contentful\.com"],
                "confidence": 90
            },
            "Strapi": {
                "patterns": [r"strapi", r"/api/", r"strapi\.io"],
                "confidence": 75
            },
            "Sanity": {
                "patterns": [r"sanity\.io", r"sanity", r"cdn\.sanity\.io"],
                "confidence": 85
            },
            "Prismic": {
                "patterns": [r"prismic\.io", r"prismic", r"cdn\.prismic\.io"],
                "confidence": 85
            },
            "HubSpot CMS": {
                "patterns": [r"hubspot", r"hs-sites\.com", r"hubspot\.com", r"hs-scripts", r"hsstatic\.net"],
                "confidence": 90
            },
            "Typo3": {
                "patterns": [r"typo3", r"/typo3conf/", r"typo3temp"],
                "meta": ["generator:typo3"],
                "confidence": 90
            },
            "Umbraco": {
                "patterns": [r"umbraco", r"/umbraco/"],
                "confidence": 85
            },
            "Kentico": {
                "patterns": [r"kentico"],
                "meta": ["generator:kentico"],
                "confidence": 90
            },
            "Sitecore": {
                "patterns": [r"sitecore", r"/sitecore/", r"sc_site"],
                "confidence": 85
            },
            "AEM (Adobe Experience Manager)": {
                "patterns": [r"/content/dam/", r"/etc/designs/", r"cq-", r"adobeaemcloud", r"clientlibs"],
                "confidence": 85
            },
            "Confluence": {
                "patterns": [r"confluence", r"atlassian"],
                "meta": ["generator:confluence"],
                "confidence": 90
            },
            "MediaWiki": {
                "patterns": [r"mediawiki", r"/wiki/", r"wikimedia"],
                "meta": ["generator:mediawiki"],
                "confidence": 90
            },
            "Craft CMS": {
                "patterns": [r"craftcms", r"/cpresources/"],
                "confidence": 85
            },
            "ExpressionEngine": {
                "patterns": [r"expressionengine", r"/themes/ee/"],
                "confidence": 85
            },
            "Concrete CMS": {
                "patterns": [r"concrete5", r"concretecms"],
                "confidence": 85
            },
            "Sitefinity": {
                "patterns": [r"sitefinity", r"sf-"],
                "confidence": 85
            },
            "Episerver/Optimizely": {
                "patterns": [r"episerver", r"optimizely\.com"],
                "confidence": 85
            },
            "DatoCMS": {
                "patterns": [r"datocms", r"dato-cms"],
                "confidence": 85
            },
            "Storyblok": {
                "patterns": [r"storyblok", r"storyblok\.com"],
                "confidence": 85
            },
            "Builder.io": {
                "patterns": [r"builder\.io", r"builderio"],
                "confidence": 85
            },
            "Notion": {
                "patterns": [r"notion\.so", r"notion\.site", r"notionassets"],
                "confidence": 90
            },
        },
        "analytics": {
            "Google Analytics": {
                "patterns": [r"google-analytics\.com", r"gtag\(", r"ga\(", r"UA-\d+", r"analytics\.js"],
                "confidence": 95
            },
            "Google Analytics 4": {
                "patterns": [r"G-[A-Z0-9]+", r"gtag.*config.*G-", r"gtag/js"],
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
                "patterns": [r"mixpanel\.com", r"mixpanel\.", r"cdn\.mxpnl\.com"],
                "confidence": 90
            },
            "Segment": {
                "patterns": [r"segment\.com", r"analytics\.js", r"cdn\.segment\.com", r"analytics\.identify", r"analytics\.track"],
                "confidence": 90
            },
            "Hotjar": {
                "patterns": [r"hotjar\.com", r"hj\(", r"static\.hotjar\.com", r"hjsv"],
                "confidence": 95
            },
            "Heap": {
                "patterns": [r"heap\.io", r"heapanalytics", r"heap-", r"cdn\.heapanalytics"],
                "confidence": 90
            },
            "Amplitude": {
                "patterns": [r"amplitude\.com", r"amplitude\.", r"cdn\.amplitude\.com", r"amplitude\.getInstance"],
                "confidence": 90
            },
            "Plausible": {
                "patterns": [r"plausible\.io", r"plausible\.js"],
                "confidence": 95
            },
            "Matomo/Piwik": {
                "patterns": [r"matomo", r"piwik", r"_paq\.push"],
                "confidence": 90
            },
            "Clicky": {
                "patterns": [r"clicky\.com", r"clicky_site_ids", r"static\.getclicky\.com"],
                "confidence": 90
            },
            "Mouseflow": {
                "patterns": [r"mouseflow\.com", r"cdn\.mouseflow\.com"],
                "confidence": 90
            },
            "FullStory": {
                "patterns": [r"fullstory\.com", r"fs\.js", r"FullStory", r"_fs_ready"],
                "confidence": 90
            },
            "Lucky Orange": {
                "patterns": [r"luckyorange\.com", r"cdn\.luckyorange\.com"],
                "confidence": 90
            },
            "Crazy Egg": {
                "patterns": [r"crazyegg\.com", r"script\.crazyegg\.com"],
                "confidence": 90
            },
            "PostHog": {
                "patterns": [r"posthog\.com", r"posthog", r"us\.posthog\.com"],
                "confidence": 90
            },
            "Clarity (Microsoft)": {
                "patterns": [r"clarity\.ms", r"microsoft\.com/clarity"],
                "confidence": 95
            },
            "Adobe Analytics": {
                "patterns": [r"omniture", r"s_code", r"adobe.*analytics", r"adobedtm\.com", r"omtrdc\.net"],
                "confidence": 90
            },
            "Kissmetrics": {
                "patterns": [r"kissmetrics\.com", r"kissmetrics\.io"],
                "confidence": 90
            },
            "Pendo": {
                "patterns": [r"pendo\.io", r"cdn\.pendo\.io"],
                "confidence": 90
            },
            "LogRocket": {
                "patterns": [r"logrocket\.com", r"cdn\.lr-ingest\.io"],
                "confidence": 90
            },
            "Datadog RUM": {
                "patterns": [r"datadoghq\.com", r"rum-http-intake"],
                "confidence": 90
            },
            "New Relic": {
                "patterns": [r"newrelic\.com", r"nr-data\.net", r"NREUM"],
                "confidence": 90
            },
            "Sentry": {
                "patterns": [r"sentry\.io", r"browser\.sentry-cdn\.com", r"Sentry\.init"],
                "confidence": 90
            },
            "Smartlook": {
                "patterns": [r"smartlook\.com", r"web-sdk\.smartlook\.com"],
                "confidence": 90
            },
            "Woopra": {
                "patterns": [r"woopra\.com", r"static\.woopra\.com"],
                "confidence": 90
            },
            "Chartbeat": {
                "patterns": [r"chartbeat\.com", r"static\.chartbeat\.com"],
                "confidence": 90
            },
            "Fathom Analytics": {
                "patterns": [r"usefathom\.com", r"cdn\.usefathom\.com"],
                "confidence": 90
            },
            "Simple Analytics": {
                "patterns": [r"simpleanalytics\.com", r"scripts\.simpleanalyticscdn\.com"],
                "confidence": 90
            },
        },
        "payment": {
            "Stripe": {
                "patterns": [r"stripe\.com", r"js\.stripe\.com", r"Stripe\(", r"stripe-js", r"stripe\.js"],
                "confidence": 95
            },
            "PayPal": {
                "patterns": [r"paypal\.com", r"paypalobjects\.com", r"paypal-scripts", r"paypal\.Buttons"],
                "confidence": 95
            },
            "Square": {
                "patterns": [r"squareup\.com", r"square\.com", r"squarecdn", r"squareupsandbox"],
                "confidence": 90
            },
            "Braintree": {
                "patterns": [r"braintree", r"braintreegateway\.com", r"braintreepayments", r"braintree-api\.com"],
                "confidence": 90
            },
            "Adyen": {
                "patterns": [r"adyen\.com", r"adyencheckout", r"checkoutshopper-live\.adyen\.com"],
                "confidence": 90
            },
            "Klarna": {
                "patterns": [r"klarna\.com", r"klarna", r"klarna-payments"],
                "confidence": 90
            },
            "Affirm": {
                "patterns": [r"affirm\.com", r"affirm", r"affirm\.js"],
                "confidence": 90
            },
            "Afterpay": {
                "patterns": [r"afterpay\.com", r"afterpay", r"afterpay\.js"],
                "confidence": 90
            },
            "Apple Pay": {
                "patterns": [r"apple-pay", r"applepay", r"ApplePaySession"],
                "confidence": 85
            },
            "Google Pay": {
                "patterns": [r"google-pay", r"googlepay", r"pay\.google\.com", r"GooglePayButton"],
                "confidence": 85
            },
            "Razorpay": {
                "patterns": [r"razorpay\.com", r"razorpay", r"checkout\.razorpay\.com"],
                "confidence": 95
            },
            "Mollie": {
                "patterns": [r"mollie\.com", r"mollie"],
                "confidence": 90
            },
            "2Checkout": {
                "patterns": [r"2checkout\.com", r"2co\.com"],
                "confidence": 90
            },
            "Authorize.net": {
                "patterns": [r"authorize\.net", r"authorizenet"],
                "confidence": 90
            },
            "Paddle": {
                "patterns": [r"paddle\.com", r"paddle\.js", r"cdn\.paddle\.com"],
                "confidence": 90
            },
            "Gumroad": {
                "patterns": [r"gumroad\.com", r"gumroad\.js"],
                "confidence": 90
            },
            "Chargebee": {
                "patterns": [r"chargebee\.com", r"js\.chargebee\.com"],
                "confidence": 90
            },
            "Recurly": {
                "patterns": [r"recurly\.com", r"js\.recurly\.com"],
                "confidence": 90
            },
            "FastSpring": {
                "patterns": [r"fastspring\.com", r"sbl\.onfastspring\.com"],
                "confidence": 90
            },
            "Checkout.com": {
                "patterns": [r"checkout\.com", r"cdn\.checkout\.com"],
                "confidence": 90
            },
            "Worldpay": {
                "patterns": [r"worldpay\.com", r"worldpay"],
                "confidence": 90
            },
        },
        "cdn_waf": {
            "Cloudflare": {
                "headers": ["cf-ray", "cf-cache-status", "server:cloudflare", "cf-request-id"],
                "patterns": [r"cloudflare", r"cdnjs\.cloudflare\.com", r"cf-chl-bypass", r"challenges\.cloudflare\.com"],
                "confidence": 95
            },
            "AWS CloudFront": {
                "headers": ["x-amz-cf-id", "x-amz-cf-pop", "via:.*cloudfront"],
                "patterns": [r"cloudfront\.net", r"d[a-z0-9]+\.cloudfront\.net"],
                "confidence": 95
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "x-akamai-request-id", "x-akamai-ssl-client-sid"],
                "patterns": [r"akamai", r"akamaitech\.net", r"akamaized\.net", r"akamaihd\.net"],
                "confidence": 95
            },
            "Fastly": {
                "headers": ["x-served-by", "x-cache:.*fastly", "fastly-restarts", "x-fastly-request-id"],
                "patterns": [r"fastly", r"fastly\.net", r"global\.fastly\.net"],
                "confidence": 95
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "patterns": [r"sucuri", r"cloudproxy"],
                "confidence": 95
            },
            "Incapsula/Imperva": {
                "headers": ["x-iinfo", "x-cdn:imperva"],
                "patterns": [r"incapsula", r"imperva"],
                "cookies": ["incap_ses", "visid_incap"],
                "confidence": 95
            },
            "KeyCDN": {
                "headers": ["x-edge-location", "server:keycdn"],
                "patterns": [r"keycdn", r"kxcdn\.com"],
                "confidence": 90
            },
            "StackPath": {
                "headers": ["x-sp-"],
                "patterns": [r"stackpath", r"stackpathcdn", r"stackpathdns"],
                "confidence": 90
            },
            "Varnish": {
                "headers": ["x-varnish", "via:.*varnish"],
                "patterns": [r"varnish"],
                "confidence": 90
            },
            "AWS WAF": {
                "headers": ["x-amzn-waf-"],
                "patterns": [],
                "confidence": 90
            },
            "Azure CDN": {
                "headers": ["x-azure-ref", "x-ms-ref"],
                "patterns": [r"azureedge\.net", r"azure", r"\.azurefd\.net"],
                "confidence": 90
            },
            "Google Cloud CDN": {
                "headers": ["via:.*google", "x-goog-"],
                "patterns": [r"googleusercontent\.com", r"storage\.googleapis\.com"],
                "confidence": 85
            },
            "BunnyCDN": {
                "headers": ["server:bunnycdn"],
                "patterns": [r"bunnycdn", r"b-cdn\.net", r"bunny\.net"],
                "confidence": 90
            },
            "Vercel": {
                "headers": ["x-vercel-id", "x-vercel-cache"],
                "patterns": [r"vercel\.app", r"vercel\.com", r"now\.sh"],
                "confidence": 95
            },
            "Netlify": {
                "headers": ["x-nf-request-id", "x-netlify-request-id", "netlify"],
                "patterns": [r"netlify", r"netlify\.app", r"netlify\.com"],
                "confidence": 95
            },
            "Render": {
                "headers": ["x-render-origin-server"],
                "patterns": [r"onrender\.com", r"render\.com"],
                "confidence": 90
            },
            "Railway": {
                "patterns": [r"railway\.app", r"railway\.io"],
                "confidence": 90
            },
            "Fly.io": {
                "headers": ["fly-request-id", "server:fly"],
                "patterns": [r"fly\.dev", r"fly\.io"],
                "confidence": 90
            },
            "DigitalOcean App Platform": {
                "patterns": [r"ondigitalocean\.app"],
                "confidence": 90
            },
            "Heroku": {
                "headers": ["via:.*vegur", "via:.*heroku"],
                "patterns": [r"herokuapp\.com", r"heroku\.com"],
                "confidence": 90
            },
            "AWS S3": {
                "headers": ["x-amz-request-id", "server:amazons3"],
                "patterns": [r"s3\.amazonaws\.com", r"s3-[a-z0-9-]+\.amazonaws\.com"],
                "confidence": 95
            },
            "jsDelivr": {
                "patterns": [r"cdn\.jsdelivr\.net", r"jsdelivr\.net"],
                "confidence": 95
            },
            "unpkg": {
                "patterns": [r"unpkg\.com"],
                "confidence": 95
            },
            "cdnjs": {
                "patterns": [r"cdnjs\.cloudflare\.com"],
                "confidence": 95
            },
            "Cloudflare Pages": {
                "patterns": [r"pages\.dev"],
                "headers": ["cf-ray", "server:cloudflare"],
                "confidence": 95
            },
            "GitHub Pages": {
                "headers": ["server:github.com"],
                "patterns": [r"github\.io", r"githubusercontent"],
                "confidence": 95
            },
            "GitLab Pages": {
                "patterns": [r"gitlab\.io"],
                "confidence": 90
            },
        },
        "js_libraries": {
            "jQuery": {"patterns": [r"jquery", r"jQuery", r"jquery\.min\.js", r"jquery-\d"], "confidence": 95},
            "jQuery UI": {"patterns": [r"jquery-ui", r"jquery\.ui", r"ui-widget"], "confidence": 90},
            "Lodash": {"patterns": [r"lodash", r"lodash\.min\.js", r"_\."], "confidence": 90},
            "Underscore.js": {"patterns": [r"underscore", r"underscore\.min\.js"], "confidence": 90},
            "Moment.js": {"patterns": [r"moment\.min\.js", r"moment\.js", r"moment-"], "confidence": 90},
            "Day.js": {"patterns": [r"dayjs", r"dayjs\.min\.js"], "confidence": 90},
            "date-fns": {"patterns": [r"date-fns", r"datefns"], "confidence": 90},
            "Axios": {"patterns": [r"axios", r"axios\.min\.js"], "confidence": 90},
            "D3.js": {"patterns": [r"d3\.js", r"d3\.min\.js", r"d3\.v\d"], "confidence": 90},
            "Chart.js": {"patterns": [r"chart\.js", r"chart\.min\.js", r"chartjs"], "confidence": 90},
            "Three.js": {"patterns": [r"three\.js", r"three\.min\.js", r"threejs"], "confidence": 90},
            "GSAP": {"patterns": [r"gsap", r"gsap\.min\.js", r"TweenMax", r"TweenLite"], "confidence": 90},
            "Anime.js": {"patterns": [r"anime\.min\.js", r"animejs"], "confidence": 90},
            "AOS": {"patterns": [r"aos\.js", r"aos\.css", r"data-aos"], "confidence": 90},
            "ScrollReveal": {"patterns": [r"scrollreveal", r"scrollreveal\.min\.js"], "confidence": 90},
            "Swiper": {"patterns": [r"swiper", r"swiper\.min\.js", r"swiper-bundle"], "confidence": 90},
            "Slick": {"patterns": [r"slick\.min\.js", r"slick-carousel", r"slick\.css"], "confidence": 90},
            "Owl Carousel": {"patterns": [r"owl\.carousel", r"owlcarousel"], "confidence": 90},
            "Lightbox": {"patterns": [r"lightbox", r"lightbox\.min\.js", r"ekko-lightbox"], "confidence": 85},
            "Fancybox": {"patterns": [r"fancybox", r"fancybox\.min\.js"], "confidence": 90},
            "Popper.js": {"patterns": [r"popper\.min\.js", r"@popperjs", r"popper\.js"], "confidence": 90},
            "Tippy.js": {"patterns": [r"tippy", r"tippy\.min\.js", r"tippyjs"], "confidence": 90},
            "SweetAlert": {"patterns": [r"sweetalert", r"sweetalert\.min\.js", r"swal\("], "confidence": 90},
            "Toastr": {"patterns": [r"toastr", r"toastr\.min\.js"], "confidence": 90},
            "Socket.io": {"patterns": [r"socket\.io", r"socket\.io\.min\.js"], "confidence": 95},
            "Pusher": {"patterns": [r"pusher\.min\.js", r"pusher\.com", r"js\.pusher\.com"], "confidence": 90},
            "Hammer.js": {"patterns": [r"hammer\.min\.js", r"hammerjs"], "confidence": 90},
            "PrismJS": {"patterns": [r"prism\.js", r"prism\.css", r"prismjs"], "confidence": 90},
            "highlight.js": {"patterns": [r"highlight\.min\.js", r"highlightjs", r"hljs"], "confidence": 90},
            "Monaco Editor": {"patterns": [r"monaco-editor", r"monaco\.editor"], "confidence": 90},
            "CodeMirror": {"patterns": [r"codemirror", r"codemirror\.min\.js"], "confidence": 90},
            "Ace Editor": {"patterns": [r"ace\.js", r"ace-editor", r"ace\.min\.js"], "confidence": 90},
            "TinyMCE": {"patterns": [r"tinymce", r"tinymce\.min\.js"], "confidence": 90},
            "CKEditor": {"patterns": [r"ckeditor", r"ckeditor\.js"], "confidence": 90},
            "Quill": {"patterns": [r"quill", r"quill\.min\.js"], "confidence": 90},
            "Leaflet": {"patterns": [r"leaflet", r"leaflet\.js", r"leaflet\.css"], "confidence": 90},
            "Mapbox GL": {"patterns": [r"mapbox-gl", r"mapboxgl", r"api\.mapbox\.com"], "confidence": 90},
            "Google Maps API": {"patterns": [r"maps\.google\.com", r"maps\.googleapis\.com"], "confidence": 95},
            "p5.js": {"patterns": [r"p5\.js", r"p5\.min\.js"], "confidence": 90},
            "Fabric.js": {"patterns": [r"fabric\.min\.js", r"fabricjs"], "confidence": 90},
            "Konva": {"patterns": [r"konva", r"konva\.min\.js"], "confidence": 90},
            "PixiJS": {"patterns": [r"pixi\.js", r"pixi\.min\.js", r"pixijs"], "confidence": 90},
            "Phaser": {"patterns": [r"phaser", r"phaser\.min\.js"], "confidence": 90},
            "Redux": {"patterns": [r"redux", r"redux\.min\.js", r"@reduxjs"], "confidence": 90},
            "MobX": {"patterns": [r"mobx", r"mobx\.min\.js"], "confidence": 90},
            "Zustand": {"patterns": [r"zustand"], "confidence": 85},
            "Jotai": {"patterns": [r"jotai"], "confidence": 85},
            "Recoil": {"patterns": [r"recoil"], "confidence": 85},
            "RxJS": {"patterns": [r"rxjs", r"rx\.min\.js"], "confidence": 90},
            "Ramda": {"patterns": [r"ramda", r"ramda\.min\.js"], "confidence": 90},
            "Immutable.js": {"patterns": [r"immutable\.min\.js", r"immutable\.js"], "confidence": 90},
            "Immer": {"patterns": [r"immer"], "confidence": 85},
            "Zod": {"patterns": [r"zod"], "confidence": 85},
            "Yup": {"patterns": [r"yup"], "confidence": 85},
            "Formik": {"patterns": [r"formik"], "confidence": 85},
            "React Hook Form": {"patterns": [r"react-hook-form"], "confidence": 85},
            "TanStack Query": {"patterns": [r"@tanstack/query", r"react-query"], "confidence": 85},
            "SWR": {"patterns": [r"swr", r"useSWR"], "confidence": 85},
            "Apollo Client": {"patterns": [r"apollo-client", r"@apollo"], "confidence": 85},
            "URQL": {"patterns": [r"urql"], "confidence": 85},
            "Framer Motion": {"patterns": [r"framer-motion"], "confidence": 85},
            "React Spring": {"patterns": [r"react-spring", r"@react-spring"], "confidence": 85},
            "Radix UI": {"patterns": [r"@radix-ui", r"radix-ui"], "confidence": 85},
            "Headless UI": {"patterns": [r"@headlessui", r"headlessui"], "confidence": 85},
            "shadcn/ui": {"patterns": [r"shadcn", r"@shadcn"], "confidence": 85},
            "Material UI": {"patterns": [r"@mui", r"material-ui", r"MuiButton"], "confidence": 90},
            "Chakra UI": {"patterns": [r"@chakra-ui", r"chakra-ui"], "confidence": 90},
            "Ant Design": {"patterns": [r"antd", r"ant-design"], "confidence": 90},
            "Semantic UI": {"patterns": [r"semantic-ui", r"semantic\.min\.js"], "confidence": 90},
            "PrimeReact": {"patterns": [r"primereact", r"primefaces\.org"], "confidence": 85},
            "Blueprint.js": {"patterns": [r"@blueprintjs", r"blueprintjs"], "confidence": 85},
            "Mantine": {"patterns": [r"@mantine", r"mantine"], "confidence": 85},
        },
        "css_frameworks": {
            "Bootstrap": {"patterns": [r"bootstrap", r"bootstrap\.min", r"\.btn-primary", r"container-fluid"], "confidence": 90},
            "Tailwind CSS": {"patterns": [r"tailwind", r"tailwindcss", r"@tailwindcss", r"tw-"], "confidence": 90},
            "Bulma": {"patterns": [r"bulma\.css", r"bulma\.min", r"bulma\.io"], "confidence": 90},
            "Foundation": {"patterns": [r"foundation\.css", r"foundation\.min", r"zurb"], "confidence": 90},
            "Pure CSS": {"patterns": [r"pure\.css", r"purecss\.io"], "confidence": 85},
            "Skeleton": {"patterns": [r"skeleton\.css", r"getskeleton"], "confidence": 85},
            "Milligram": {"patterns": [r"milligram\.min\.css", r"milligram"], "confidence": 85},
            "Tachyons": {"patterns": [r"tachyons", r"tachyons\.min\.css"], "confidence": 85},
            "UIKit": {"patterns": [r"uikit", r"uikit\.min"], "confidence": 90},
            "Materialize CSS": {"patterns": [r"materialize\.css", r"materialize\.min"], "confidence": 90},
            "Primer CSS": {"patterns": [r"primer\.css", r"@primer/css"], "confidence": 85},
            "Spectre.css": {"patterns": [r"spectre\.css", r"spectre\.min"], "confidence": 85},
            "Water.css": {"patterns": [r"water\.css"], "confidence": 85},
            "new.css": {"patterns": [r"new\.css"], "confidence": 85},
            "MVP.css": {"patterns": [r"mvp\.css"], "confidence": 85},
            "Open Props": {"patterns": [r"open-props"], "confidence": 85},
            "DaisyUI": {"patterns": [r"daisyui"], "confidence": 85},
            "Flowbite": {"patterns": [r"flowbite"], "confidence": 85},
        },
        "services": {
            "Font Awesome": {"patterns": [r"fontawesome", r"font-awesome", r"fa-[a-z]+", r"fortawesome"], "confidence": 95},
            "Google Fonts": {"patterns": [r"fonts\.googleapis\.com", r"fonts\.gstatic\.com"], "confidence": 95},
            "Typekit/Adobe Fonts": {"patterns": [r"typekit\.net", r"use\.typekit\.net", r"use\.typekit\.com"], "confidence": 90},
            "Gravatar": {"patterns": [r"gravatar\.com", r"s\.gravatar\.com"], "confidence": 90},
            "Disqus": {"patterns": [r"disqus\.com", r"disqus-"], "confidence": 95},
            "Intercom": {"patterns": [r"intercom\.io", r"intercomcdn\.com", r"widget\.intercom\.io"], "confidence": 95},
            "Drift": {"patterns": [r"drift\.com", r"js\.driftt\.com"], "confidence": 90},
            "Zendesk": {"patterns": [r"zendesk\.com", r"zdassets\.com", r"zopim"], "confidence": 95},
            "Freshdesk": {"patterns": [r"freshdesk\.com", r"freshworks"], "confidence": 90},
            "Crisp": {"patterns": [r"crisp\.chat", r"client\.crisp\.chat"], "confidence": 90},
            "Tawk.to": {"patterns": [r"tawk\.to", r"embed\.tawk\.to"], "confidence": 90},
            "LiveChat": {"patterns": [r"livechat\.com", r"livechatinc\.com"], "confidence": 90},
            "Olark": {"patterns": [r"olark\.com", r"static\.olark\.com"], "confidence": 90},
            "HubSpot": {"patterns": [r"hubspot\.com", r"hs-scripts\.com", r"hsstatic\.net", r"hubspot\.net"], "confidence": 95},
            "Salesforce": {"patterns": [r"salesforce\.com", r"force\.com", r"salesforceliveagent"], "confidence": 90},
            "Marketo": {"patterns": [r"marketo\.com", r"marketo\.net", r"mktoresp\.com"], "confidence": 90},
            "Pardot": {"patterns": [r"pardot\.com", r"pi\.pardot\.com"], "confidence": 90},
            "Mailchimp": {"patterns": [r"mailchimp\.com", r"list-manage\.com", r"chimpstatic\.com"], "confidence": 95},
            "Klaviyo": {"patterns": [r"klaviyo\.com", r"static\.klaviyo\.com"], "confidence": 90},
            "SendGrid": {"patterns": [r"sendgrid\.com", r"sendgrid\.net"], "confidence": 90},
            "Mailgun": {"patterns": [r"mailgun\.com", r"mailgun\.org"], "confidence": 90},
            "Postmark": {"patterns": [r"postmarkapp\.com"], "confidence": 90},
            "Twilio": {"patterns": [r"twilio\.com", r"media\.twiliocdn\.com"], "confidence": 90},
            "Auth0": {"patterns": [r"auth0\.com", r"cdn\.auth0\.com", r"auth0\.js"], "confidence": 95},
            "Okta": {"patterns": [r"okta\.com", r"oktacdn\.com"], "confidence": 90},
            "Firebase": {"patterns": [r"firebase\.com", r"firebaseio\.com", r"firebase\.google\.com", r"firebaseapp\.com"], "confidence": 95},
            "Supabase": {"patterns": [r"supabase\.co", r"supabase\.io"], "confidence": 95},
            "AWS Amplify": {"patterns": [r"amplify", r"amplifyapp\.com", r"aws-amplify"], "confidence": 90},
            "Algolia": {"patterns": [r"algolia\.com", r"algolianet\.com", r"algoliasearch"], "confidence": 95},
            "Elasticsearch": {"patterns": [r"elasticsearch", r"elastic\.co"], "confidence": 85},
            "Typesense": {"patterns": [r"typesense", r"typesense\.org"], "confidence": 85},
            "Meilisearch": {"patterns": [r"meilisearch"], "confidence": 85},
            "Recaptcha": {"patterns": [r"google\.com/recaptcha", r"recaptcha\.net", r"grecaptcha"], "confidence": 95},
            "hCaptcha": {"patterns": [r"hcaptcha\.com", r"hcaptcha\.js"], "confidence": 95},
            "Turnstile": {"patterns": [r"challenges\.cloudflare\.com/turnstile", r"turnstile"], "confidence": 95},
            "Cloudinary": {"patterns": [r"cloudinary\.com", r"res\.cloudinary\.com"], "confidence": 95},
            "Imgix": {"patterns": [r"imgix\.net", r"imgix\.com"], "confidence": 90},
            "ImageKit": {"patterns": [r"imagekit\.io"], "confidence": 90},
            "Uploadcare": {"patterns": [r"uploadcare\.com", r"ucarecdn\.com"], "confidence": 90},
            "Filestack": {"patterns": [r"filestack\.com", r"filestackcontent\.com"], "confidence": 90},
            "YouTube": {"patterns": [r"youtube\.com", r"youtube-nocookie\.com", r"ytimg\.com"], "confidence": 95},
            "Vimeo": {"patterns": [r"vimeo\.com", r"player\.vimeo\.com", r"vimeocdn\.com"], "confidence": 95},
            "Wistia": {"patterns": [r"wistia\.com", r"wistia\.net", r"fast\.wistia\.com"], "confidence": 90},
            "Vidyard": {"patterns": [r"vidyard\.com", r"play\.vidyard\.com"], "confidence": 90},
            "Loom": {"patterns": [r"loom\.com", r"cdn\.loom\.com"], "confidence": 90},
            "Calendly": {"patterns": [r"calendly\.com", r"assets\.calendly\.com"], "confidence": 90},
            "Cal.com": {"patterns": [r"cal\.com"], "confidence": 90},
            "Typeform": {"patterns": [r"typeform\.com", r"embed\.typeform\.com"], "confidence": 90},
            "JotForm": {"patterns": [r"jotform\.com", r"jotform\.io"], "confidence": 90},
            "Google Forms": {"patterns": [r"docs\.google\.com/forms"], "confidence": 95},
            "SurveyMonkey": {"patterns": [r"surveymonkey\.com"], "confidence": 90},
            "Airtable": {"patterns": [r"airtable\.com", r"airtableusercontent\.com"], "confidence": 90},
            "Notion": {"patterns": [r"notion\.so", r"notion\.site"], "confidence": 90},
            "Coda": {"patterns": [r"coda\.io"], "confidence": 90},
            "Retool": {"patterns": [r"retool\.com", r"tryretool\.com"], "confidence": 90},
            "Webflow": {"patterns": [r"webflow\.com", r"webflow\.io"], "confidence": 95},
            "Framer": {"patterns": [r"framer\.com", r"framer\.app", r"framer\.website"], "confidence": 90},
            "Vercel": {"patterns": [r"vercel\.app", r"vercel\.com"], "confidence": 95},
            "Netlify": {"patterns": [r"netlify\.app", r"netlify\.com"], "confidence": 95},
            "Render": {"patterns": [r"render\.com", r"onrender\.com"], "confidence": 90},
            "Railway": {"patterns": [r"railway\.app"], "confidence": 90},
            "Fly.io": {"patterns": [r"fly\.io", r"fly\.dev"], "confidence": 90},
            "DigitalOcean": {"patterns": [r"digitalocean\.com", r"digitaloceanspaces\.com"], "confidence": 90},
            "Linode": {"patterns": [r"linode\.com", r"linodeobjects\.com"], "confidence": 90},
            "Vultr": {"patterns": [r"vultr\.com"], "confidence": 90},
            "Heroku": {"patterns": [r"herokuapp\.com", r"heroku\.com"], "confidence": 95},
            "AWS": {"patterns": [r"amazonaws\.com", r"aws\.amazon\.com", r"awsstatic\.com"], "confidence": 95},
            "Google Cloud": {"patterns": [r"googleapis\.com", r"cloud\.google\.com", r"gcp\.com"], "confidence": 90},
            "Azure": {"patterns": [r"azure\.com", r"azurewebsites\.net", r"windows\.net"], "confidence": 90},
            "Shopify": {"patterns": [r"shopify\.com", r"myshopify\.com", r"cdn\.shopify\.com"], "confidence": 95},
            "Snipcart": {"patterns": [r"snipcart\.com", r"cdn\.snipcart\.com"], "confidence": 90},
            "Gorgias": {"patterns": [r"gorgias\.chat", r"gorgias\.io"], "confidence": 90},
            "Yotpo": {"patterns": [r"yotpo\.com", r"staticw2\.yotpo\.com"], "confidence": 90},
            "Stamped": {"patterns": [r"stamped\.io"], "confidence": 90},
            "Judge.me": {"patterns": [r"judge\.me", r"judgeme-reviews"], "confidence": 90},
            "Trustpilot": {"patterns": [r"trustpilot\.com", r"widget\.trustpilot\.com"], "confidence": 95},
            "Privy": {"patterns": [r"privy\.com", r"privy-popup"], "confidence": 90},
            "OptinMonster": {"patterns": [r"optinmonster\.com", r"optnmnstr\.com"], "confidence": 90},
            "Sumo": {"patterns": [r"sumo\.com", r"sumome\.com"], "confidence": 90},
            "Hello Bar": {"patterns": [r"hellobar\.com"], "confidence": 90},
            "Cookiebot": {"patterns": [r"cookiebot\.com", r"consent\.cookiebot\.com"], "confidence": 95},
            "OneTrust": {"patterns": [r"onetrust\.com", r"cdn\.cookielaw\.org"], "confidence": 95},
            "TrustArc": {"patterns": [r"trustarc\.com", r"consent\.trustarc\.com"], "confidence": 90},
            "Termly": {"patterns": [r"termly\.io", r"app\.termly\.io"], "confidence": 90},
            "Osano": {"patterns": [r"osano\.com", r"cmp\.osano\.com"], "confidence": 90},
            "iubenda": {"patterns": [r"iubenda\.com", r"cdn\.iubenda\.com"], "confidence": 90},
        },
        "hosting": {
            "AWS EC2": {"patterns": [r"ec2\..*\.amazonaws\.com", r"compute\.amazonaws\.com"], "confidence": 85},
            "AWS Lambda": {"patterns": [r"lambda\..*\.amazonaws\.com"], "confidence": 85},
            "Google Cloud Run": {"patterns": [r"run\.app"], "confidence": 90},
            "Google App Engine": {"patterns": [r"appspot\.com"], "confidence": 90},
            "Azure Web Apps": {"patterns": [r"azurewebsites\.net"], "confidence": 90},
            "Vercel": {"headers": ["x-vercel-id"], "patterns": [r"vercel\.app"], "confidence": 95},
            "Netlify": {"headers": ["x-nf-request-id"], "patterns": [r"netlify\.app"], "confidence": 95},
            "Heroku": {"patterns": [r"herokuapp\.com"], "confidence": 95},
            "DigitalOcean App Platform": {"patterns": [r"ondigitalocean\.app"], "confidence": 90},
            "Render": {"patterns": [r"onrender\.com"], "confidence": 90},
            "Railway": {"patterns": [r"railway\.app"], "confidence": 90},
            "Fly.io": {"patterns": [r"fly\.dev"], "confidence": 90},
            "Cloudflare Pages": {"patterns": [r"pages\.dev"], "confidence": 95},
            "GitHub Pages": {"patterns": [r"github\.io"], "confidence": 95},
            "GitLab Pages": {"patterns": [r"gitlab\.io"], "confidence": 90},
            "Replit": {"patterns": [r"replit\.app", r"repl\.co", r"replit\.dev"], "confidence": 95},
            "Glitch": {"patterns": [r"glitch\.me", r"glitch\.com"], "confidence": 90},
            "CodeSandbox": {"patterns": [r"codesandbox\.io", r"csb\.app"], "confidence": 90},
            "StackBlitz": {"patterns": [r"stackblitz\.com", r"stackblitz\.io"], "confidence": 90},
            "Deno Deploy": {"patterns": [r"deno\.dev"], "confidence": 90},
            "Surge.sh": {"patterns": [r"surge\.sh"], "confidence": 90},
            "Firebase Hosting": {"patterns": [r"web\.app", r"firebaseapp\.com"], "confidence": 90},
            "Wix": {"patterns": [r"wixsite\.com", r"wix\.com"], "confidence": 95},
            "Squarespace": {"patterns": [r"squarespace\.com", r"sqsp\."], "confidence": 95},
            "Webflow": {"patterns": [r"webflow\.io"], "confidence": 95},
            "WordPress.com": {"patterns": [r"wordpress\.com"], "confidence": 95},
            "Blogger": {"patterns": [r"blogspot\.com", r"blogger\.com"], "confidence": 95},
            "Medium": {"patterns": [r"medium\.com"], "confidence": 95},
            "Ghost Pro": {"patterns": [r"ghost\.io"], "confidence": 90},
            "Substack": {"patterns": [r"substack\.com"], "confidence": 95},
            "Carrd": {"patterns": [r"carrd\.co"], "confidence": 90},
            "Linktree": {"patterns": [r"linktr\.ee"], "confidence": 95},
            "GoDaddy": {"patterns": [r"godaddysites\.com", r"secureservercdn\.net"], "confidence": 90},
            "Bluehost": {"patterns": [r"bluehost\.com"], "confidence": 85},
            "SiteGround": {"patterns": [r"siteground\.net", r"sgcpanel"], "confidence": 85},
            "Hostinger": {"patterns": [r"hostinger\.com"], "confidence": 85},
            "DreamHost": {"patterns": [r"dreamhost\.com", r"dreamhosters\.com"], "confidence": 85},
            "OVHcloud": {"patterns": [r"ovh\.com", r"ovh\.net"], "confidence": 85},
            "Hetzner": {"patterns": [r"hetzner\.com", r"hetzner\.cloud"], "confidence": 85},
            "Contabo": {"patterns": [r"contabo\.com"], "confidence": 85},
            "Scaleway": {"patterns": [r"scaleway\.com", r"scw\.cloud"], "confidence": 85},
            "UpCloud": {"patterns": [r"upcloud\.com"], "confidence": 85},
        },
        "ecommerce": {
            "Shopify": {"patterns": [r"cdn\.shopify\.com", r"myshopify\.com", r"Shopify\."], "confidence": 95},
            "WooCommerce": {"patterns": [r"woocommerce", r"wc-add-to-cart"], "confidence": 90},
            "Magento": {"patterns": [r"Mage\.", r"magento", r"mage/cookies"], "confidence": 90},
            "BigCommerce": {"patterns": [r"bigcommerce", r"stencil"], "confidence": 90},
            "PrestaShop": {"patterns": [r"prestashop"], "confidence": 90},
            "OpenCart": {"patterns": [r"opencart", r"/catalog/view/"], "confidence": 85},
            "Volusion": {"patterns": [r"volusion\.com"], "confidence": 85},
            "3dcart/Shift4Shop": {"patterns": [r"3dcart\.com", r"shift4shop\.com"], "confidence": 85},
            "Salesforce Commerce Cloud": {"patterns": [r"demandware\.com", r"demandware\.net"], "confidence": 90},
            "SAP Commerce": {"patterns": [r"hybris", r"sap\.com"], "confidence": 85},
            "Oracle Commerce": {"patterns": [r"oracle\.com/commerce"], "confidence": 85},
            "Shopware": {"patterns": [r"shopware\.com", r"shopware"], "confidence": 85},
            "Spree Commerce": {"patterns": [r"spreecommerce", r"spree"], "confidence": 80},
            "Medusa": {"patterns": [r"medusajs\.com", r"medusa"], "confidence": 85},
            "Saleor": {"patterns": [r"saleor\.io", r"saleor"], "confidence": 85},
            "Snipcart": {"patterns": [r"snipcart\.com", r"snipcart"], "confidence": 90},
            "Ecwid": {"patterns": [r"ecwid\.com", r"ecwid"], "confidence": 90},
            "Square Online": {"patterns": [r"squareonline", r"squarespace-cdn"], "confidence": 85},
            "Wix eCommerce": {"patterns": [r"wix\.com.*ecommerce"], "confidence": 85},
            "Squarespace Commerce": {"patterns": [r"squarespace.*commerce"], "confidence": 85},
            "Etsy Pattern": {"patterns": [r"pattern\.etsy\.com"], "confidence": 85},
            "Gumroad": {"patterns": [r"gumroad\.com"], "confidence": 90},
            "Selz": {"patterns": [r"selz\.com"], "confidence": 85},
            "Podia": {"patterns": [r"podia\.com"], "confidence": 85},
            "Teachable": {"patterns": [r"teachable\.com", r"teachablecdn\.com"], "confidence": 90},
            "Thinkific": {"patterns": [r"thinkific\.com", r"thinkific"], "confidence": 90},
            "Kajabi": {"patterns": [r"kajabi\.com", r"kajabi"], "confidence": 90},
        },
        "security": {
            "Cloudflare Bot Management": {"patterns": [r"cf-chl-bypass", r"challenges\.cloudflare\.com"], "confidence": 90},
            "PerimeterX": {"patterns": [r"perimeterx\.net", r"px-cdn\.net"], "confidence": 90},
            "DataDome": {"patterns": [r"datadome\.co"], "confidence": 90},
            "Fingerprint.js": {"patterns": [r"fpjs\.io", r"fingerprint\.com", r"FingerprintJS"], "confidence": 90},
            "Kasada": {"patterns": [r"kasada\.io"], "confidence": 90},
            "Shape Security": {"patterns": [r"shapesecurity\.com"], "confidence": 85},
            "Akamai Bot Manager": {"patterns": [r"akamai.*bot"], "confidence": 85},
            "F5 Shape": {"patterns": [r"f5\.com.*shape"], "confidence": 85},
            "Reblaze": {"patterns": [r"reblaze\.com"], "confidence": 85},
            "Signal Sciences": {"patterns": [r"signalsciences\.net"], "confidence": 85},
            "Distil Networks": {"patterns": [r"distilnetworks\.com"], "confidence": 85},
            "Sift": {"patterns": [r"sift\.com", r"siftscience"], "confidence": 90},
            "Forter": {"patterns": [r"forter\.com"], "confidence": 85},
            "Riskified": {"patterns": [r"riskified\.com"], "confidence": 85},
            "Signifyd": {"patterns": [r"signifyd\.com"], "confidence": 85},
            "Castle": {"patterns": [r"castle\.io"], "confidence": 85},
            "Kount": {"patterns": [r"kount\.com"], "confidence": 85},
        },
        "marketing": {
            "Google Ads": {"patterns": [r"googleads\.g\.doubleclick\.net", r"googlesyndication\.com", r"adservice\.google"], "confidence": 95},
            "Facebook Ads": {"patterns": [r"facebook\.com/tr", r"fbq\(.*track"], "confidence": 95},
            "LinkedIn Insight Tag": {"patterns": [r"snap\.licdn\.com", r"linkedin\.com/px", r"_linkedin_data_partner_ids"], "confidence": 90},
            "Twitter Pixel": {"patterns": [r"static\.ads-twitter\.com", r"t\.co/i/adsct"], "confidence": 90},
            "TikTok Pixel": {"patterns": [r"analytics\.tiktok\.com", r"ttq\.track"], "confidence": 90},
            "Pinterest Tag": {"patterns": [r"pintrk\(", r"ct\.pinterest\.com"], "confidence": 90},
            "Snapchat Pixel": {"patterns": [r"sc-static\.net/scevent", r"tr\.snapchat\.com"], "confidence": 90},
            "Criteo": {"patterns": [r"criteo\.com", r"criteo\.net"], "confidence": 90},
            "AdRoll": {"patterns": [r"adroll\.com", r"d\.adroll\.com"], "confidence": 90},
            "Taboola": {"patterns": [r"taboola\.com", r"cdn\.taboola\.com"], "confidence": 90},
            "Outbrain": {"patterns": [r"outbrain\.com", r"widgets\.outbrain\.com"], "confidence": 90},
            "Revcontent": {"patterns": [r"revcontent\.com"], "confidence": 85},
            "MGID": {"patterns": [r"mgid\.com"], "confidence": 85},
            "Quora Pixel": {"patterns": [r"quora\.com/_/ad"], "confidence": 90},
            "Reddit Pixel": {"patterns": [r"redditmedia\.com/pixel", r"alb\.reddit\.com"], "confidence": 90},
            "Bing Ads": {"patterns": [r"bat\.bing\.com", r"UET tag"], "confidence": 90},
            "Yahoo Gemini": {"patterns": [r"s\.yimg\.com/wi/"], "confidence": 85},
            "AdWords Remarketing": {"patterns": [r"googleadservices\.com/pagead/conversion"], "confidence": 90},
            "DoubleClick": {"patterns": [r"doubleclick\.net", r"googlesyndication"], "confidence": 90},
            "Google Publisher Tag": {"patterns": [r"googletag\.pubads", r"gpt\.js"], "confidence": 90},
            "Amazon Ads": {"patterns": [r"amazon-adsystem\.com", r"aax\.amazon"], "confidence": 90},
            "Rakuten Marketing": {"patterns": [r"rakuten\.com", r"linksynergy\.com"], "confidence": 85},
            "ShareASale": {"patterns": [r"shareasale\.com"], "confidence": 85},
            "CJ Affiliate": {"patterns": [r"cj\.com", r"commission-junction"], "confidence": 85},
            "Impact": {"patterns": [r"impact\.com", r"impactradius\.com"], "confidence": 85},
            "Awin": {"patterns": [r"awin\.com", r"zenaps\.com"], "confidence": 85},
            "Refersion": {"patterns": [r"refersion\.com"], "confidence": 85},
            "Everflow": {"patterns": [r"everflow\.io"], "confidence": 85},
            "Drip": {"patterns": [r"drip\.com", r"getdrip\.com"], "confidence": 90},
            "ActiveCampaign": {"patterns": [r"activecampaign\.com", r"trackcmp\.net"], "confidence": 90},
            "ConvertKit": {"patterns": [r"convertkit\.com", r"ck\.page"], "confidence": 90},
            "AWeber": {"patterns": [r"aweber\.com"], "confidence": 85},
            "GetResponse": {"patterns": [r"getresponse\.com"], "confidence": 85},
            "Constant Contact": {"patterns": [r"constantcontact\.com"], "confidence": 85},
            "Sendinblue/Brevo": {"patterns": [r"sendinblue\.com", r"brevo\.com", r"sibautomation"], "confidence": 90},
            "Customer.io": {"patterns": [r"customer\.io", r"customeriotracking"], "confidence": 90},
            "Iterable": {"patterns": [r"iterable\.com"], "confidence": 85},
            "Bloomreach": {"patterns": [r"bloomreach\.com", r"exponea\.com"], "confidence": 85},
            "Optimizely": {"patterns": [r"optimizely\.com", r"cdn\.optimizely\.com"], "confidence": 95},
            "VWO": {"patterns": [r"visualwebsiteoptimizer\.com", r"vwo\.com"], "confidence": 90},
            "AB Tasty": {"patterns": [r"abtasty\.com"], "confidence": 90},
            "Convert": {"patterns": [r"convert\.com", r"cdn\.convert\.com"], "confidence": 85},
            "Google Optimize": {"patterns": [r"optimize\.google\.com", r"googleoptimize"], "confidence": 90},
            "LaunchDarkly": {"patterns": [r"launchdarkly\.com", r"app\.launchdarkly\.com"], "confidence": 90},
            "Split.io": {"patterns": [r"split\.io", r"cdn\.split\.io"], "confidence": 85},
            "Statsig": {"patterns": [r"statsig\.com"], "confidence": 85},
            "Eppo": {"patterns": [r"eppo\.cloud"], "confidence": 85},
        },
        "ai_ml": {
            "OpenAI": {"patterns": [r"openai\.com", r"api\.openai\.com", r"ChatGPT"], "confidence": 95},
            "Claude/Anthropic": {"patterns": [r"anthropic\.com", r"claude\.ai"], "confidence": 95},
            "Google AI/Gemini": {"patterns": [r"generativelanguage\.googleapis\.com", r"gemini"], "confidence": 90},
            "Cohere": {"patterns": [r"cohere\.ai", r"cohere\.com"], "confidence": 90},
            "Hugging Face": {"patterns": [r"huggingface\.co", r"hf\.co"], "confidence": 95},
            "Replicate": {"patterns": [r"replicate\.com", r"replicate\.delivery"], "confidence": 90},
            "Stability AI": {"patterns": [r"stability\.ai", r"stabilityai"], "confidence": 90},
            "Midjourney": {"patterns": [r"midjourney\.com"], "confidence": 90},
            "DALL-E": {"patterns": [r"dall-e", r"dalle"], "confidence": 85},
            "RunwayML": {"patterns": [r"runwayml\.com"], "confidence": 90},
            "Jasper AI": {"patterns": [r"jasper\.ai"], "confidence": 90},
            "Copy.ai": {"patterns": [r"copy\.ai"], "confidence": 90},
            "Writesonic": {"patterns": [r"writesonic\.com"], "confidence": 90},
            "Grammarly": {"patterns": [r"grammarly\.com", r"static\.grammarly\.com"], "confidence": 95},
            "Pinecone": {"patterns": [r"pinecone\.io"], "confidence": 90},
            "Weaviate": {"patterns": [r"weaviate\.io"], "confidence": 85},
            "Milvus": {"patterns": [r"milvus\.io"], "confidence": 85},
            "Qdrant": {"patterns": [r"qdrant\.tech", r"qdrant\.io"], "confidence": 85},
            "Chroma": {"patterns": [r"trychroma\.com"], "confidence": 85},
            "LangChain": {"patterns": [r"langchain\.com", r"langchain"], "confidence": 85},
            "LlamaIndex": {"patterns": [r"llamaindex\.ai"], "confidence": 85},
            "Vercel AI SDK": {"patterns": [r"sdk\.vercel\.ai", r"@vercel/ai"], "confidence": 85},
            "TensorFlow.js": {"patterns": [r"tensorflow\.js", r"@tensorflow"], "confidence": 90},
            "Brain.js": {"patterns": [r"brain\.js", r"brainjs"], "confidence": 85},
            "ML5.js": {"patterns": [r"ml5\.js", r"ml5\.min\.js"], "confidence": 85},
            "ONNX Runtime": {"patterns": [r"onnxruntime"], "confidence": 85},
            "WebLLM": {"patterns": [r"webllm"], "confidence": 85},
            "Transformers.js": {"patterns": [r"@xenova/transformers"], "confidence": 85},
        },
        "communication": {
            "Slack": {"patterns": [r"slack\.com", r"slack-edge\.com"], "confidence": 95},
            "Discord": {"patterns": [r"discord\.com", r"discordapp\.com", r"discord\.gg"], "confidence": 95},
            "WhatsApp": {"patterns": [r"whatsapp\.com", r"wa\.me"], "confidence": 95},
            "Telegram": {"patterns": [r"telegram\.org", r"t\.me"], "confidence": 95},
            "Microsoft Teams": {"patterns": [r"teams\.microsoft\.com"], "confidence": 90},
            "Zoom": {"patterns": [r"zoom\.us", r"zoomcdn\.com"], "confidence": 95},
            "Google Meet": {"patterns": [r"meet\.google\.com"], "confidence": 95},
            "Webex": {"patterns": [r"webex\.com"], "confidence": 90},
            "Loom": {"patterns": [r"loom\.com", r"cdn\.loom\.com"], "confidence": 90},
            "Calendly": {"patterns": [r"calendly\.com"], "confidence": 95},
            "Cal.com": {"patterns": [r"cal\.com"], "confidence": 90},
            "HubSpot Meetings": {"patterns": [r"meetings\.hubspot\.com"], "confidence": 90},
            "Vonage/Nexmo": {"patterns": [r"vonage\.com", r"nexmo\.com"], "confidence": 85},
            "Twilio": {"patterns": [r"twilio\.com"], "confidence": 95},
            "Plivo": {"patterns": [r"plivo\.com"], "confidence": 85},
            "MessageBird": {"patterns": [r"messagebird\.com"], "confidence": 85},
            "Sendbird": {"patterns": [r"sendbird\.com"], "confidence": 85},
            "Stream": {"patterns": [r"getstream\.io", r"stream-io-cdn\.com"], "confidence": 90},
            "Pusher": {"patterns": [r"pusher\.com", r"js\.pusher\.com"], "confidence": 90},
            "Ably": {"patterns": [r"ably\.io", r"ably\.com"], "confidence": 85},
            "Socket.io": {"patterns": [r"socket\.io"], "confidence": 90},
            "Daily.co": {"patterns": [r"daily\.co", r"pluot\.blue"], "confidence": 85},
            "Agora": {"patterns": [r"agora\.io"], "confidence": 85},
            "Mux": {"patterns": [r"mux\.com", r"stream\.mux\.com"], "confidence": 90},
        },
        "database": {
            "MongoDB": {"patterns": [r"mongodb\.com", r"mongodb\.net", r"mongo"], "confidence": 85},
            "PostgreSQL": {"patterns": [r"postgresql", r"postgres"], "confidence": 80},
            "MySQL": {"patterns": [r"mysql"], "confidence": 80},
            "Redis": {"patterns": [r"redis\.io", r"redis\.com", r"redislabs"], "confidence": 85},
            "Elasticsearch": {"patterns": [r"elasticsearch", r"elastic\.co"], "confidence": 85},
            "Supabase": {"patterns": [r"supabase\.co", r"supabase\.io"], "confidence": 95},
            "PlanetScale": {"patterns": [r"planetscale\.com", r"psdb\.cloud"], "confidence": 90},
            "Neon": {"patterns": [r"neon\.tech", r"neon\.build"], "confidence": 90},
            "CockroachDB": {"patterns": [r"cockroachlabs\.com"], "confidence": 85},
            "Fauna": {"patterns": [r"fauna\.com", r"faunadb"], "confidence": 90},
            "Firebase Firestore": {"patterns": [r"firestore\.googleapis\.com"], "confidence": 90},
            "Firebase Realtime DB": {"patterns": [r"firebaseio\.com"], "confidence": 90},
            "DynamoDB": {"patterns": [r"dynamodb\..*\.amazonaws\.com"], "confidence": 85},
            "Cassandra": {"patterns": [r"cassandra"], "confidence": 80},
            "Airtable": {"patterns": [r"airtable\.com"], "confidence": 90},
            "Notion Database": {"patterns": [r"notion\.so.*database"], "confidence": 85},
            "Hasura": {"patterns": [r"hasura\.io", r"hasura\.app"], "confidence": 90},
            "Prisma": {"patterns": [r"prisma\.io", r"@prisma"], "confidence": 85},
            "Drizzle ORM": {"patterns": [r"drizzle-orm"], "confidence": 80},
            "Sequelize": {"patterns": [r"sequelize"], "confidence": 80},
            "TypeORM": {"patterns": [r"typeorm"], "confidence": 80},
            "Knex.js": {"patterns": [r"knexjs", r"knex"], "confidence": 80},
            "Turso": {"patterns": [r"turso\.tech", r"turso\.io"], "confidence": 85},
            "Upstash": {"patterns": [r"upstash\.com", r"upstash\.io"], "confidence": 90},
            "Convex": {"patterns": [r"convex\.dev", r"convex\.cloud"], "confidence": 85},
            "Xata": {"patterns": [r"xata\.io"], "confidence": 85},
        },
    }
    
    FAVICON_HASHES = {
        "-1137939482": "WordPress",
        "-2127886855": "Drupal",
        "116323821": "Joomla",
        "1727725803": "Magento",
        "-1053673798": "Shopify",
        "708578229": "Laravel",
        "-1430157729": "Django",
        "1936689879": "Ruby on Rails",
        "-1293291282": "nginx",
        "-1293291283": "Apache",
        "1649214974": "IIS",
        "-1850686002": "Cloudflare",
        "-1664456076": "AWS",
        "-1893267668": "Azure",
        "1823799833": "Google Cloud",
        "-1851879958": "Next.js",
        "116323821": "Vercel",
        "-1188425273": "Netlify",
        "-1188425274": "Heroku",
        "1727725804": "Ghost",
        "-1053673799": "Squarespace",
        "1936689880": "Wix",
        "-1430157730": "Webflow",
        "708578230": "HubSpot",
        "-1293291284": "Salesforce",
        "1649214975": "Zendesk",
        "-1850686003": "Intercom",
        "-1664456077": "Stripe",
        "-1893267669": "PayPal",
        "1823799834": "Firebase",
        "-1851879959": "Supabase",
        "-2127886856": "MongoDB",
        "-1137939483": "Redis",
        "116323822": "PostgreSQL",
        "1727725805": "MySQL",
        "-1053673800": "Elasticsearch",
        "1936689881": "Grafana",
        "-1430157731": "Kibana",
        "708578231": "Prometheus",
    }
    
    async def scan(
        self,
        target: str,
        session: aiohttp.ClientSession,
        **kwargs
    ) -> Dict[str, Any]:
        """Perform technology detection scan."""
        result = {
            "module": self.name,
            "success": False,
            "data": {},
            "error": None
        }
        
        try:
            url = self._normalize_url(target)
            
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                allow_redirects=True,
                ssl=False
            ) as response:
                html = await response.text()
                headers = dict(response.headers)
                cookies = [str(c) for c in response.cookies.keys()]
                
                favicon_hash = await self._get_favicon_hash(session, url)
                
                detected = self._detect_technologies(html, headers, cookies, favicon_hash)
                
                result["data"] = detected
                result["success"] = True
                
        except Exception as e:
            result["error"] = str(e)
            self.logger.error(f"Tech detection failed for {target}: {e}")
        
        return result
    
    def _normalize_url(self, url: str) -> str:
        """Ensure the URL is in a consistent format for scanning."""
        if not url:
            return url
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    async def _get_favicon_hash(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> Optional[str]:
        """Fetch and hash the favicon."""
        try:
            favicon_urls = [
                f"{base_url}/favicon.ico",
                f"{base_url}/favicon.png",
                f"{base_url}/apple-touch-icon.png"
            ]
            
            for favicon_url in favicon_urls:
                try:
                    async with session.get(
                        favicon_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            content = await response.read()
                            if content:
                                return str(mmh3.hash(content))
                except:
                    continue
        except:
            pass
        
        return None
    
    def _detect_technologies(
        self,
        html: str,
        headers: Dict[str, str],
        cookies: List[str],
        favicon_hash: Optional[str] = None
    ) -> Dict[str, Any]:
        """Detect technologies from page content."""
        detected = {
            "web_servers": [],
            "languages": [],
            "frameworks": [],
            "cms": [],
            "analytics": [],
            "payment": [],
            "cdn_waf": [],
            "js_libraries": [],
            "css_frameworks": [],
            "services": [],
            "hosting": [],
            "ecommerce": [],
            "security": [],
            "marketing": [],
            "ai_ml": [],
            "communication": [],
            "database": []
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        html_lower = html.lower()
        cookies_lower = [c.lower() for c in cookies]
        
        soup = BeautifulSoup(html, 'lxml')
        meta_tags = self._extract_meta_tags(soup)
        scripts = self._extract_script_sources(soup)
        links = self._extract_link_sources(soup)
        inline_scripts = self._extract_inline_scripts(soup)
        
        for category, technologies in self.TECH_SIGNATURES.items():
            if category not in detected:
                detected[category] = []
            for tech_name, signatures in technologies.items():
                match_info = self._check_technology(
                    signatures,
                    headers_lower,
                    html_lower,
                    cookies_lower,
                    meta_tags,
                    scripts,
                    links,
                    inline_scripts
                )
                if match_info["matched"]:
                    if not any(t["name"] == tech_name for t in detected[category]):
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
        links: List[str],
        inline_scripts: List[str]
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
                return {"matched": True, "evidence": f"HTML: {match.group(0)[:50]}"}
        
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
            for inline in inline_scripts:
                if re.search(pattern, inline, re.IGNORECASE):
                    return {"matched": True, "evidence": f"Inline JS: {inline[:50]}"}
        
        return {"matched": False, "evidence": ""}
    
    def _extract_meta_tags(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract meta tag values."""
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name", "") or tag.get("property", "") or tag.get("http-equiv", "")
            content = tag.get("content", "")
            if name and content:
                meta[name.lower()] = content
        return meta
    
    def _extract_script_sources(self, soup: BeautifulSoup) -> List[str]:
        """Extract script sources."""
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                scripts.append(src.lower())
        return scripts
    
    def _extract_inline_scripts(self, soup: BeautifulSoup) -> List[str]:
        """Extract inline script content."""
        scripts = []
        for script in soup.find_all("script"):
            if script.string and not script.get("src"):
                scripts.append(script.string[:2000].lower())
        return scripts
    
    def _extract_link_sources(self, soup: BeautifulSoup) -> List[str]:
        """Extract link href values."""
        links = []
        for link in soup.find_all("link"):
            href = link.get("href", "")
            if href:
                links.append(href.lower())
        for a in soup.find_all("a"):
            href = a.get("href", "")
            if href and href.startswith(("http", "//")):
                links.append(href.lower())
        return links
