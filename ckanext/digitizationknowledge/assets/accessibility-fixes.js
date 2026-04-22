(function () {
    function patchDataTablesResizeIframes(root) {
        var scope = root || document;
        var iframes = [];

        if (scope.nodeType === 1 && scope.tagName === 'IFRAME') {
            iframes.push(scope);
        }

        var found = scope.querySelectorAll
            ? scope.querySelectorAll('iframe[src="about:blank"][data="about:blank"]')
            : [];

        Array.prototype.forEach.call(found, function (iframe) {
            iframes.push(iframe);
        });

        iframes.forEach(function (iframe) {
            iframe.setAttribute('aria-hidden', 'true');
            iframe.setAttribute('tabindex', '-1');
        });
    }

    function init() {
        patchDataTablesResizeIframes(document);

        if (window.MutationObserver) {
            var observer = new MutationObserver(function (mutations) {
                mutations.forEach(function (mutation) {
                    mutation.addedNodes.forEach(function (node) {
                        if (node && node.nodeType === 1) {
                            patchDataTablesResizeIframes(node);
                        }
                    });
                });
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();