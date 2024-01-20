// Xsolla Paybar Widget
if (typeof(XPBWidget) == 'undefined') {
    var xpbMessages =
    {
        paystation: {ru: 'PayStation', en: 'PayStation'},
        show_more: {ru: 'ÐŸÐ¾ÐºÐ°Ð·Ð°Ñ‚ÑŒ ÐµÑ‰Ðµ', en: 'Show more', de: 'Mehr anzeigen'},
        previous: {ru: '&larr;', en: '&larr;'},
        next: {ru: '&rarr;', en: '&rarr;'}
    };

    var XPBWidget =
    {
        __defaultHost: 'https://secure.xsolla.com',
        __pluginDir: '/paybar/jswidget/',
        __pluginUrl: false,
        __apiScript: '/paybar/api/api.php',
        __apiUrl: false,
        __apiParams: ['project', 'v0', 'v1', 'v2', 'v3', 'hidden', 'email', 'phone',
            'out', 'currency', 'local', 'country', 'sign', 'userip',
            'icon_set', 'marketplace', 'mobile', 'fixed_instances', 'categories', 'signparams', 'prime', 'description', 'payment_amount', 'payment_currency'],
        __options: {element_id: 'paybar', type: {id: 'lightbox'}, css: 'default.css', messages: {}, template: { id: 'inline' },
            project: null, v0: null, v1: null, v2: null, v3: null, hidden: null, email: null, phone: null,
            out: null, currency: null, local: null, country: null, sign: null, userip: null,
            icon_set: 1, marketplace: 16, mobile: null, fixed_instances: false, categories: null, 'signparams': null, prime: null, 'description': null, 'payment_amount': null, 'payment_currency': null,
            icon_count: null, other: null, other_count: null, slide_down: false, // Deprecated
            errorCallback: null, doneCallback: null, beforeSubmit: null,
            itemTemplate: '<span><a href="%HREF%" target="_blank"><img src="%ICON_SRC%" />%NAME%</a></span>'},
        __initialized: false,
        __loaded: false,
        __element: false,
        __templateParams: null,
        __controller: null,
        __jqXHR: null,
        __fancyboxVersion: null,
        __data: {},


        init: function (options) {
            var self = this;
            for (var index in this.__options) if (typeof(options[index]) != 'undefined' && options[index] !== null) this.__options[index] = options[index];

            if (typeof(options.scripthost) != 'undefined' && options.scripthost) {
                this.__pluginUrl = options.scripthost + this.__pluginDir;
                this.__apiUrl = options.scripthost + this.__apiScript;
            }
            else {
                this.__pluginUrl = this.__defaultHost + this.__pluginDir;
                this.__apiUrl = this.__defaultHost + this.__apiScript;
            }

            if (this.__initialized) {
                if (this.__jqXHR) this.__jqXHR.abort();

                if (this.__loaded) self.initWidget();
                else self.loadCore();
            }
            else {
                DOMReady.add(function () {
                    self.loadCore();
                });

                this.__initialized = true;
            }
            return this;
        },

        loadCore: function () {
            var self = this;
            var scripts = [];
            var isJqueryRequired = false;
            if (!window.jQuery) {
                scripts[scripts.length] = '//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js';
                isJqueryRequired = true;
            }

            var loader = new XLoader();

            loader.requireScript
            (scripts, function () {
                if (isJqueryRequired) jQuery.noConflict();
                self.loadPlugins();
            });
        },

        loadPlugins: function () {
            var self = this;
            var loader = new XLoader();
            var styles = [];
            var scripts = [];

            if (!jQuery.isPlainObject(this.__options['type'])) this.__options['type'] = {id: this.__options['type']};
            if (typeof(this.__options['type'].id) == 'undefined') this.__options['type'].id = null;
            if (typeof(this.__options['type'].version) == 'undefined' && jQuery.inArray(parseInt(this.__options['type'].version, 10), [1, 2])) this.__options['type'].version = 2;

            if (self.fancyboxVersion() !== false) this.__options['type'].version = self.fancyboxVersion();

            if (this.__options['css']) {
                var localPattern = /^[\w/-]+\.css$/;
                var urlPattern = /^((http|https):)?\/.*$/i;
                if (localPattern.test(this.__options['css'])) styles[styles.length] = this.__pluginUrl + 'css/' + this.__options['css'];
                else if (urlPattern.test(this.__options['css'])) styles[styles.length] = this.__options['css'];
            }

            if (self.fancyboxVersion() === false) {
                switch (this.__options['type'].version) {
                    case 1:
                    {
                        styles[styles.length] = this.__pluginUrl + 'css/fancybox/jquery.fancybox-1.3.4.css';
                        scripts[scripts.length] = this.__pluginUrl + 'js/jquery.mousewheel-3.0.4.pack.js';
                        scripts[scripts.length] = this.__pluginUrl + 'js/jquery.fancybox-1.3.4.pack.js';
                    }
                        break;
                    case 2:
                    {
                        styles[styles.length] = this.__pluginUrl + 'css/fancybox2/jquery.fancybox.css';
                        scripts[scripts.length] = this.__pluginUrl + 'js/jquery.fancybox-2.1.5.pack.js';
                    }
                        break;
                }
            }

            loader.loadStyle(styles);
            loader.requireScript
            (scripts, function () {
                self.__fancyboxVersion = null;
                self.initWidget();
            });
        },

        fancyboxVersion: function () {
            if (this.__fancyboxVersion !== null) return this.__fancyboxVersion;
            if (typeof(jQuery.fancybox) == 'undefined') return this.__fancyboxVersion = false;
            if (typeof(jQuery.fancybox.version) != 'undefined') return this.__fancyboxVersion = parseInt(jQuery.fancybox.version, 10)
            return this.__fancyboxVersion = 1;
        },

        initWidget: function () {
            this.__loaded = true;

            this.__element = typeof(this.__options['element_id']) == 'string' ? jQuery('#' + this.__options['element_id']) : jQuery(this.__options['element_id']);
            if (!this.__element.length) return;

            this.__element.addClass('xpb-widget').find('.xpb-payment-option, .xpb-container').remove();

            var options = this.__options['template'];
            switch (this.__options['template'].id) {
                default:
                case 'inline':
                {
                    this.__controller = new XPBInlineController();
                    if (this.__options['icon_count'] !== null) options['icon_count'] = this.__options['icon_count'];
                    if (this.__options['other'] !== null) options['other'] = this.__options['other'];
                }
                    break;
                case 'show_more':
                {
                    this.__controller = new XPBShowMoreController();
                    if (this.__options['icon_count'] !== null) options['icon_count'] = this.__options['icon_count'];
                    if (this.__options['other_count'] !== null) options['other_count'] = this.__options['other_count'];
                }
                    break;
                case 'slide':
                {
                    this.__controller = new XPBSlideController();
                    if (this.__options['icon_count'] !== null) options['icon_count'] = this.__options['icon_count'];
                }
                    break;
            }
            this.__controller.run(this, options);
        },

        loadList: function (start, count, other, callback) {
            var self = this;

            var apiData = {};
            for (var i = 0; i < this.__apiParams.length; i++) {
                if (typeof(this.__options[this.__apiParams[i]]) != 'undefined' && this.__options[this.__apiParams[i]] !== null) {
                    var val = this.__options[this.__apiParams[i]];
                    if (val === true) val = '1'; else if (val === false) val = '0';
                    apiData[this.__apiParams[i]] = val;
                }
            }

            apiData['other'] = other ? '1' : '0';
            apiData['start'] = start;
            apiData['icon_count'] = count;

            this.__jqXHR = jQuery.ajax
            ({
                url: this.__apiUrl + '?callback=?',
                data: apiData,
                dataType: 'jsonp',
                cache: false
            }).done(function (response) {
                    if (typeof(response.success) != 'undefined' && response.success && jQuery.isArray(response.data)) {
                        var list = jQuery();
                        for (var i = 0; i < response.data.length; i++) {
                            var item = response.data[i];
                            self.__data[item.pid] = item;
                            var isOther = typeof(item.other) != 'undefined' && item.other;
                            list = list.add(self.getListItem(item.pid, item.name, isOther ? null : item.icon, item.href, { other: isOther }));
                        }
                        var remaining = response.showMore;
                        callback(list, remaining);
                    }
                    else if (typeof(response.error) != 'undefined' && response.error) {
                        self.showFailOption();
                        self.errorHandler(response.error, 'api');
                    }
                }).fail(function (jqXHR, textStatus) {
                    self.showFailOption();
                    self.errorHandler(textStatus, 'ajax');
                });
        },

        getListItem: function (pid, name, icon, href, options) {
            var self = this;
            if (typeof(options) == 'undefined') options = {};
            options = jQuery.extend({
                id: null,
                className: null,
                other: false,
                blank: false,
                loading: false,
                fail: false,
                more: false
            }, options);

            var tpl = self.__options['itemTemplate'];
            tpl = tpl.split('%NAME%').join(name ? name : '');
            tpl = tpl.split('%ICON_SRC%').join(icon ? icon : this.__pluginUrl + 'img/blank.png');
            tpl = tpl.split('%HREF%').join(href ? href : '#link');
            tpl = tpl.split('%PID%').join(pid ? pid : '0');


            var option = jQuery(tpl);
            if (option.length > 1 || option.is('a')) option = jQuery('<span />').append(option);

            option.addClass('xpb-payment-option');
            option.attr('xpb-payment', pid);

            if (options.other) {
                option.addClass('xpb-other-option');
            }
            if (options.blank) {
                option.find('[href="#link"]').removeAttr('href');
                option.addClass('xpb-blank-option');
            }
            if (options.loading) {
                option.addClass('xpb-loading-option');
            }
            if (options.fail) {
                option.addClass('xpb-fail-option');
            }
            if (options.more) {
                option.addClass('xpb-more-option');
            }
            if (options.id !== null) option.attr('id', options.id);
            if (options.className !== null) option.addClass(options.className);

            if(typeof(self.__options.beforeSubmit) === 'function'){
                option.bind('click', function(eventObject){
                    option.attr('href', this.__pluginUrl+'/wait.php');
                    return self.__options.beforeSubmit(eventObject);
                })
            }

            // Deprecated
            if (typeof(self.__options['template'].closeCallback) != 'undefined') self.__options['type'].onClosed = self.__options['template'].closeCallback;

            if (self.__options['type'].id == 'lightbox' && !options.blank && !options.more) {
                if (self.__options['type'].version == 1) {
                    var fancyParams = jQuery.extend(self.__getFancyboxDefaultParams(), self.__options['type']);

                    option.find('a[href]').click(function () {
                        fancyParams.href = jQuery(this).attr('href');
                        jQuery.fancybox(fancyParams);
                        jQuery.fancybox.showActivity();

                        return false;
                    });
                }
                else if (self.__options['type'].version == 2) {
                    // Compatibility with v1
                    if (typeof(self.__options['template'].onClosed) != 'undefined') self.__options['type'].afterClose = self.__options['template'].onClosed;
                    if (typeof(self.__options['template'].showCloseButton) != 'undefined') self.__options['type'].closeBtn = self.__options['template'].showCloseButton;
                    if (typeof(self.__options['template'].autoDimensions) != 'undefined') self.__options['type'].autoSize = self.__options['template'].autoDimensions;
                    if (typeof(self.__options['template'].autoScale) != 'undefined') self.__options['type'].fitToView = self.__options['template'].autoScale;

                    var fancyParams = jQuery.extend(self.__getFancyboxDefaultParams(), self.__options['type']);

                    option.find('a[href]').click(function () {
                        fancyParams.href = jQuery(this).attr('href');
                        jQuery.fancybox(fancyParams);

                        return false;
                    });
                }
            }

            return option;
        },

        __getFancyboxDefaultParams: function(){
            switch(this.__options['type'].version){
                case 2:
                    return {
                        'type': 'iframe',
                        'closeBtn': true,
                        'width': '95%',
                        'height': '95%',
                        'autoSize': false,
                        'fitToView': false,
                        'href': '#',
                        'padding': 10,
                        'onCancel': function () {
                        },
                        'afterClose': function () {
                        },
                        'afterLoad': function () {
                        }
                    }
                //version 1
                default:
                    return {
                        'type': 'iframe',
                        'showCloseButton': true,
                        'width': '95%',
                        'height': '95%',
                        'autoDimensions': false,
                        'autoScale': false,
                        'href': '#',
                        'opacity': 0.6,
                        'overlayColor': '#000',
                        'onCancel': function () {
                        },
                        'onClosed': function () {
                        },
                        'onComplete': function () {
                            jQuery('#fancybox-frame').load(function () {
                                jQuery.fancybox.hideActivity();
                            });
                        }
                }
            };
        },

        getElement: function () {
            return this.__element;
        },

        showFailOption: function () {
            this.__element.find('.xpb-payment-option.xpb-loading-option').removeClass('xpb-loading-option');
        },

        getTranslation: function (code) {
            var local = this.__options['local'] ? this.__options['local'] : 'en';
            if (typeof(this.__options['messages'][code]) != 'undefined' && typeof(this.__options['messages'][code][local]) != 'undefined') return this.__options['messages'][code][local];
            else return (typeof(xpbMessages[code][local]) != 'undefined' ? xpbMessages[code][local] : xpbMessages[code]['en']);
        },

        errorHandler: function (message, category) {
            if (typeof(this.__options['errorCallback']) === 'function') this.__options['errorCallback'](message, category);
            else if ((typeof console == "object") && message) console.log('Paybar: ' + message + ' at ' + category);
        },

        doneHandler: function () {
            if (typeof(this.__options['doneCallback']) === 'function') this.__options['doneCallback']();
        },

        newWindowOpen: function(el){
            var link = this.setPaymentData(el);
            window.open(link, 'PBWindow');
        },

        lightboxOpen: function(el, lightboxparams){
            var self = this;
                var link = this.setPaymentData(el);
                var fancyParams = jQuery.extend(self.__getFancyboxDefaultParams(), lightboxparams);
                fancyParams.href = link;
                jQuery.fancybox(fancyParams);
                return false;
        },

        setPaymentData: function(el, params){
            params = params || {};
            var pid = jQuery(el).attr('xpb-payment');
            if(this.__data[pid] == undefined){
                return false;
            }

            var data = this.__data[pid].data;

            for(var i in params){
                data.params[i] = params[i];
            }
            var url = '';
            for(var i in data.params){
                if(data.params[i] != null){
                    url += encodeURIComponent(i)+'='+encodeURIComponent(data.params[i])+'&';
                }
            }
            url = data.host+url.substring(0, url.length - 1);
            return url;
        },

        getPaymentData: function(el){
            var pid = jQuery(el).attr('xpb-payment');
            if(this.__data[pid] == undefined){
                return false;
            }
            return this.__data[pid].data.params;
        }
    };

    var XPBInlineController = function () {
    };
    XPBInlineController.prototype =
    {
        __widget: null,
        __options: { icon_count: 5, other: true },

        run: function (widget, options) {
            this.__widget = widget;
            for (index in this.__options) if (typeof(options[index]) != 'undefined' && options[index] !== null) this.__options[index] = options[index];

            this.__widget.getElement().find('.xpb-more-option').remove();
            for (var i = 0; i < this.__options['icon_count']; i++) {
                this.__widget.getElement().append(this.__widget.getListItem(null, null, null, null, { blank: true, loading: true }));
            }

            this.__widget.loadList(0, this.__options['icon_count'], this.__options['other'], function (list, remaining) {
                widget.getElement().find('.xpb-loading-option').remove();
                widget.getElement().append(list);
                widget.doneHandler();
            });
        }
    };

    var XPBShowMoreController = function () {
    };
    XPBShowMoreController.prototype =
    {
        __widget: null,
        __options: { icon_count: 5, other_count: 5, limit: null, other: false, slide_down: false },
        __showMore: null,
        __defaultSlideDownTime: 250,

        run: function (widget, options) {
            this.__widget = widget;
            for (index in this.__options) if (typeof(options[index]) != 'undefined' && options[index] !== null) this.__options[index] = options[index];

            this.loadList();
        },

        loadList: function () {
            var self = this;
            var widget = this.__widget;
            var start = this.__widget.getElement().find('.xpb-payment-option:not(.xpb-blank-option):not(.xpb-more-option)').length;
            var count = start ? this.__options['other_count'] : this.__options['icon_count'];

            if (this.__showMore !== null) count = Math.min(this.__showMore, count);
            if (this.__options['limit'] !== null) count = Math.min(this.__options['limit'] - start, count);

            var isOther = this.__options['other'] && this.__options['limit'] !== null && start + count >= this.__options['limit']

            this.__widget.getElement().find('.xpb-more-option').remove();
            for (var i = 0; i < count; i++) {
                this.__widget.getElement().append(this.__widget.getListItem(null, null, null, null, { blank: true, loading: true }));
            }

            this.__widget.loadList(start, count, isOther, function (list, remaining) {
                widget.getElement().find('.xpb-loading-option').remove();
                widget.getElement().append(list);
                if (self.__options['slide_down']) {
                    self.detectMeasurements();
                    if (!widget['init_slide_down']) {
                        var originalHeight = self.__itemOuterHeight;
                        widget.getElement()
                            .css({
                                'overflow': 'hidden',
                                'height': self.__itemOuterHeight + 'px'
                            });
                        widget['init_slide_down'] = true;
                    } else {
                        var animTime = (typeof(self.__options['slide_down']) == 'number') ? self.__options['slide_down'] : self.__defaultSlideDownTime;
                        var perRow = Math.floor (widget.getElement().width() / self.__itemOuterWidth);
                        var totalRows = Math.ceil(widget.getElement().children().length / perRow);
                        var targetHeight = totalRows * self.__itemOuterHeight;
                        widget.getElement().animate({
                            'height': targetHeight.toString() + 'px'
                        }, animTime);
                    }
                }
                if (remaining && !isOther) {
                    self.__showMore = remaining;
                    widget.getElement().append(widget.getListItem(null, widget.getTranslation('show_more'), null, null, { more: true }))
                        .find('.xpb-more-option [href="#link"]').click(function () {
                            self.loadList();
                            return false;
                        });
                }
                widget.doneHandler();
            });
        },

        detectMeasurements: function () {
            var item = this.__widget.getListItem(null, null, null, null, { blank: true }).hide().appendTo(this.__widget.getElement());
            this.__itemWidth = item.width();
            this.__itemHeight = item.height();
            this.__itemOuterWidth = item.outerWidth(true);
            this.__itemOuterHeight = item.outerHeight(true);
            item.remove();
        }
    };

    var XPBSlideController = function () {
    };
    XPBSlideController.prototype =
    {
        __widget: null,
        __options: { icon_count: 5, shift_count: 3, animation_speed: 200, other: false, limit: null, slide_on_hover: false },
        __loaded: 0,
        __listSize: 0,
        __container: null,
        __frame: null,
        __slider: null,
        __element: null,
        __itemWidth: null,
        __initialCount: 0,

        run: function (widget, options) {
            this.__widget = widget;
            for (index in this.__options) if (typeof(options[index]) != 'undefined' && options[index] !== null) this.__options[index] = options[index];

            this.__element = this.__widget.getElement();
            var children = this.__element.children().detach();
            this.__container = jQuery('<div />').addClass('xpb-container').hide().appendTo(this.__element);
            this.__frame = jQuery('<div />').addClass('xpb-frame').appendTo(this.__container);
            this.__slider = jQuery('<div />').addClass('xpb-slider').css({'left': 0, 'position': 'relative'}).append(children).appendTo(this.__frame);

            this.__initialCount = children.length;

            var self = this;

            var updateWidth = null;
            updateWidth = function () {
                self.detectWidth();
                if (self.__itemWidth > 5) self.arrangeElements();
                else setTimeout(updateWidth, 100);
            };
            updateWidth();

            this.loadList();
        },

        arrangeElements: function () {
            var self = this;
            var width = self.__itemWidth * self.__options['icon_count'];
            self.__container.show().width(width);
            self.__frame.show().width(width);

            self.__container.append(jQuery('<a />').attr('href', '#prev')
                .html(self.__widget.getTranslation('previous'))
                .addClass('xpb-prev')
                .bind('click' + (self.__options['slide_on_hover'] ? ' mouseenter' : ''), function () {
                    if (jQuery(this).is('.xpb-disabled')) return false;
                    if (self.__slider.is(':animated')) return false;

                    var left = parseInt(self.__slider.css('left'));
                    var shift = self.__itemWidth * self.__options['shift_count'];
                    self.__slider.animate
                    (
                        {'left': Math.min(left + shift, 0)},
                        self.__options['animation_speed'],
                        function () {
                            setTimeout(function () {
                                self.updateButtons();
                            }, 1);
                        }
                    );

                    self.updateButtons();
                    return false;
                }));

            self.__container.append(jQuery('<a />').attr('href', '#next')
                .html(self.__widget.getTranslation('next'))
                .addClass('xpb-next')
                .bind('click' + (self.__options['slide_on_hover'] ? ' mouseenter' : ''), function () {
                    if (jQuery(this).is('.xpb-disabled')) return false;
                    if (self.__slider.is(':animated')) return false;

                    var left = parseInt(self.__slider.css('left'));
                    var shift = Math.min((self.__listSize - self.__options['icon_count'] + self.__initialCount) * self.__itemWidth + left, self.__itemWidth * self.__options['shift_count']);

                    self.__slider.animate
                    (
                        {'left': left - shift},
                        self.__options['animation_speed'],
                        function () {
                            setTimeout(function () {
                                self.updateButtons();
                            }, 1);
                        }
                    );

                    self.updateButtons();
                    self.loadList();
                    return false;
                }));

            self.updateButtons();
        },

        updateButtons: function () {
            var prev = this.__container.find('.xpb-prev');
            var next = this.__container.find('.xpb-next');

            if (!this.__loaded) {
                prev.addClass('xpb-disabled');
                next.addClass('xpb-disabled');
                return;
            }

            var left = parseInt(this.__slider.css('left'));

            prev.toggleClass('xpb-disabled', left >= 0);
            next.toggleClass('xpb-disabled', left <= -(this.__listSize - this.__options['icon_count'] + this.__initialCount) * this.__itemWidth);
        },

        loadList: function () {
            var self = this;
            var widget = this.__widget;
            var start = this.__widget.getElement().find('.xpb-payment-option').length;
            var count = (start ? self.__options['shift_count'] : this.__options['icon_count']) + self.__options['shift_count'];

            if (this.__loaded && (self.__listSize - start <= 0)) return;
            if (this.__loaded) count = Math.min(this.__listSize - start, count);

            var loadingList = jQuery([]);
            for (var i = 0; i < count; i++) {
                loadingList = loadingList.add(this.__widget.getListItem(null, null, null, null, { blank: true, loading: true }));
            }
            this.__slider.append(loadingList);

            var other = false;
            if (self.__options['limit'] !== null && (count > self.__options['limit'] - start)) {
                count = self.__options['limit'] - start;
                other = self.__options['other'];
            }

            this.__widget.loadList(start, count, other, function (list, remaining) {
                for (var i = 0; i < list.length; i++) {
                    jQuery(loadingList[i]).replaceWith(jQuery(list[i]));
                }
                self.__loaded += list.length;
                self.__listSize = start + list.length + remaining;
                if (self.__options['limit'] !== null) self.__listSize = Math.min(self.__listSize, self.__options['limit'] + (self.__options['other'] ? 1 : 0));

                self.updateButtons();

                widget.doneHandler();
            });
        },

        detectWidth: function () {
            var item = this.__widget.getListItem(null, null, null, null, { blank: true }).hide().appendTo(this.__element);
            this.__itemWidth = item.width();
            item.remove();
        }
    };

    var XLoader = function () {
    };
    XLoader.prototype =
    {
        requireScript: function (scripts, callback) {
            this.loadCount = 0;
            this.totalRequired = scripts.length;
            this.callback = callback;

            if (!scripts.length) {
                this.callback.call();
                return;
            }
            for (var i = 0; i < scripts.length; i++) this.appendScript(scripts[i]);
        },

        scriptLoaded: function (evt) {
            this.loadCount++;
            if (this.loadCount == this.totalRequired && typeof this.callback == 'function') this.callback.call();
        },

        appendScript: function (src) {
            var self = this;
            var jsEmbededTag = document.createElement('SCRIPT');
            jsEmbededTag.type = "text/javascript";
            jsEmbededTag.async = true;
            jsEmbededTag.src = src;

            if (jsEmbededTag.addEventListener) {
                jsEmbededTag.addEventListener('load', function (e) {
                    self.scriptLoaded(e);
                }, false);
            }
            else if (jsEmbededTag.attachEvent) {
                jsEmbededTag.attachEvent('onreadystatechange', function (e) {
                    if (jsEmbededTag.readyState == 'loaded' || jsEmbededTag.readyState == 'complete') self.scriptLoaded(e);
                }, false);
            }
            else {
                jsEmbededTag.onreadystatechange = function (e) {
                    if (jsEmbededTag.readyState == 'loaded' || jsEmbededTag.readyState == 'complete') self.scriptLoaded(e);
                };
            }

            var head = document.getElementsByTagName('HEAD')[0];
            head.appendChild(jsEmbededTag);
        },

        loadStyle: function (styles) {
            var head = document.getElementsByTagName('HEAD')[0];

            for (var i = 0; i < styles.length; i++) {
                if (!styles[i]) continue;
                var cssEmbededTag = document.createElement('LINK');
                cssEmbededTag.type = 'text/css';
                cssEmbededTag.rel = 'stylesheet';
                cssEmbededTag.href = styles[i];
                head.appendChild(cssEmbededTag);
            }
        }
    };

    (function (window) {
        window.DOMReady = (function () {
            var fns = [],
                isReady = false,
                errorHandler = null,
                run = function (fn, args) {
                    try {
                        fn.apply(this, args || []);
                    } catch (err) {
                        if (errorHandler)
                            errorHandler.call(this, err);
                    }
                },
                ready = function () {
                    isReady = true;
                    for (var x = 0; x < fns.length; x++)
                        run(fns[x].fn, fns[x].args || []);
                    fns = [];
                };

            this.setOnError = function (fn) {
                errorHandler = fn;
                return this;
            };

            this.add = function (fn, args) {
                if (isReady) {
                    run(fn, args);
                } else {
                    fns[fns.length] = {
                        fn: fn,
                        args: args
                    };
                }

                return this;
            };

            if (window.addEventListener) {
                window.document.addEventListener('DOMContentLoaded', function () {
                    ready();
                }, false);
            } else {
                (function () {
                    if (!window.document.uniqueID && window.document.expando)
                        return;
                    var tempNode = window.document.createElement('document:ready');
                    try {
                        tempNode.doScroll('left');
                        ready();
                    } catch (err) {
                        setTimeout(arguments.callee, 0);
                    }
                })();
            }
            return this;
        })();
    })(window);

}

function ucfirst(str) {
    var f = str.charAt(0).toUpperCase();
    return f + str.toLowerCase().substr(1, str.length - 1);
}

function getScriptHost(url) {
    if (url.indexOf('http://') != -1 || url.indexOf('https://') != -1 || url.indexOf('//') == 0) {
        var host = url.substr(0, url.indexOf('/', url.indexOf('/') + 2));
        return host;
    }
    return false;
}
