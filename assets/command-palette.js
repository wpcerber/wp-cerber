/**
 *	Copyright (C) 2015-26 CERBER TECH INC., https://wpcerber.com
 */

/**
 * Offers WP Cerber navigation commands in the native WordPress Command Palette.
 *
 * The configuration comes from the crb_command_palette variable printed by
 * crb_cmd_palette_enqueue_assets(). Its stop_words member is a list of search queries no command
 * is offered for, and its min_query_length member is the number of characters a query must have
 * at least. The navigation entries, each one
 * {command_id: string, label: string, search_terms: string[], destination_url: string},
 * come in one of two ways:
 *
 * - entries member: the list itself, printed into the page;
 * - entries_request member: {url: string, action: string, nonce: string}, the admin-ajax request
 *   that delivers the list, see crb_cmd_palette_send_entries(). It is sent once per page load,
 *   when the palette is first searched.
 *
 * This script is the whole registration layer: it treats all entries alike and knows nothing
 * about what kind of location an entry leads to. Choosing a command only navigates.
 *
 * The commands are offered through a command loader instead of being registered one by one.
 * The palette matches registered commands fuzzily: a command is listed when the typed
 * characters occur in its label in the same order, however far apart. With many long labels
 * that fills the results with unrelated settings. A loader receives the typed text and decides
 * which commands to offer, so only the commands that contain the text literally are offered.
 *
 * The palette calls a loader without a context only while it is open and its search field is
 * not empty. The first call of the loader hook therefore tells that the palette is being used,
 * which is when the entries are requested. No palette event needs to be observed.
 */
(function (wp, palette_config) {
    'use strict';

    // Do nothing where the palette API is missing, the page then works as it did without this script

    if (!wp || !wp.data || !wp.element || !wp.commands || !wp.commands.store
        || !palette_config || !Array.isArray(palette_config.stop_words)
        || !Number.isInteger(palette_config.min_query_length)) {
        return;
    }

    const entries_request = palette_config.entries_request;
    const is_inline_mode = Array.isArray(palette_config.entries);

    const is_on_demand_mode = !is_inline_mode && !!entries_request && typeof window.fetch === 'function'
        && typeof entries_request.url === 'string' && typeof entries_request.action === 'string'
        && typeof entries_request.nonce === 'string';

    if (!is_inline_mode && !is_on_demand_mode) {
        return;
    }

    const min_query_length = palette_config.min_query_length;

    // Stop words are compared with the typed text in the form the typed text is brought to

    const stop_words = palette_config.stop_words.map(crb_normalize_search_text);

    // Delivery states of the navigation entries

    const ENTRIES_NOT_REQUESTED = 'not_requested';
    const ENTRIES_LOADING = 'loading';
    const ENTRIES_READY = 'ready';
    const ENTRIES_FAILED = 'failed';

    // The commands and the state of their delivery live here for the life of the page, not in
    // hook state: the palette mounts its loaders anew every time it is opened, so hook state
    // would be lost on closing the palette, and a new request would be sent on every opening

    let searchable_commands = [];
    let entries_state = ENTRIES_NOT_REQUESTED;
    let entries_promise = null;

    if (is_inline_mode) {
        searchable_commands = crb_build_searchable_commands(palette_config.entries);
        entries_state = ENTRIES_READY;
    }

    wp.data.dispatch(wp.commands.store).registerCommandLoader({
        name: 'wp-cerber/navigation',
        category: 'view',
        hook: crb_use_matching_commands
    });

    /**
     * Command loader hook: returns the commands that contain the text typed into the palette.
     *
     * The palette calls it as a React hook on every render of the palette. A command matches
     * when its label or one of its search terms contains the typed text as it is, regardless of
     * letter case, with whitespace and hyphens treated alike.
     *
     * No command is offered for a query that is too generic, because the palette is shared
     * with WordPress and other plugins: when the typed text is shorter than the minimum query
     * length, or when the whole typed text equals a stop word. A stop word inside a longer query
     * has no effect.
     *
     * In the on-demand mode the first call starts the request for the entries, and the hook
     * renders again once the request is settled, whether it succeeded or failed.
     *
     * @param {{search: string}} palette_state The state of the palette, search is the typed text.
     *
     * @returns {{commands: Object[], isLoading: boolean}} Matching commands in the order of the
     *          navigation entries. Loading is reported while the entries are not delivered yet
     *          and the typed text is a query commands would be offered for.
     */
    function crb_use_matching_commands(palette_state) {
        const typed_text = crb_normalize_search_text(palette_state.search || '');

        // The delivery state of the first render: setting it renders the hook again when the
        // delivery state changes, the commands themselves are read from the shared state

        const [rendered_state, set_rendered_state] = wp.element.useState(entries_state);

        wp.element.useEffect(function () {

            // The request may have settled between the first render and this effect, for instance
            // when the palette was reopened while it was pending. That render must not stay stale.

            if (entries_state === ENTRIES_READY || entries_state === ENTRIES_FAILED) {
                if (rendered_state !== entries_state) {
                    set_rendered_state(entries_state);
                }

                return undefined;
            }

            let is_mounted = true;

            crb_request_entries().then(function () {
                if (is_mounted) {
                    set_rendered_state(entries_state);
                }
            });

            return function () {
                is_mounted = false;
            };
        }, []);

        // The length is counted in characters: Array.from() splits a string by code points,
        // while the length property counts UTF-16 units and so counts some characters twice

        const is_searchable_query = Array.from(typed_text).length >= min_query_length
            && stop_words.indexOf(typed_text) === -1;

        const matching_commands = wp.element.useMemo(function () {
            if (!is_searchable_query || entries_state !== ENTRIES_READY) {
                return [];
            }

            return searchable_commands.filter(function (searchable_command) {
                return searchable_command.searchable_text.indexOf(typed_text) !== -1;
            }).map(function (searchable_command) {
                return searchable_command.command;
            });
        }, [typed_text, entries_state]);

        const is_loading = is_searchable_query
            && (entries_state === ENTRIES_NOT_REQUESTED || entries_state === ENTRIES_LOADING);

        return {commands: matching_commands, isLoading: is_loading};
    }

    /**
     * Requests the navigation entries from the server, once per page load.
     *
     * Every later call returns the promise of the first one, whatever its outcome: a failed
     * request is not repeated, because the usual causes, such as a request blocked by a firewall
     * or a nonce expired in a page left open, would fail again on every keystroke. Reloading the
     * page makes a new attempt. The reason of a failure is written to the browser console, and
     * WP Cerber then offers no commands on the page.
     *
     * @returns {Promise<void>} Settles when the delivery state is ready or failed, never rejects.
     */
    function crb_request_entries() {
        if (entries_promise) {
            return entries_promise;
        }

        entries_state = ENTRIES_LOADING;

        const request_fields = new URLSearchParams();
        request_fields.append('action', entries_request.action);
        request_fields.append('ajax_nonce', entries_request.nonce);

        entries_promise = window.fetch(entries_request.url, {
            method: 'POST',
            credentials: 'same-origin',
            body: request_fields
        }).then(function (http_response) {
            if (!http_response.ok) {
                throw new Error('HTTP status ' + http_response.status);
            }

            return http_response.json();
        }).then(function (response_payload) {
            if (!response_payload || response_payload.success !== true
                || !response_payload.data || !Array.isArray(response_payload.data.entries)) {
                throw new Error('Unexpected response format');
            }

            searchable_commands = crb_build_searchable_commands(response_payload.data.entries);
            entries_state = ENTRIES_READY;
        }).catch(function (request_error) {
            entries_state = ENTRIES_FAILED;
            window.console.error('WP Cerber: unable to load Command Palette commands. ' + request_error.message);
        });

        return entries_promise;
    }

    /**
     * Builds a palette command for every navigation entry, together with the text a search is
     * matched against.
     *
     * @param {Object[]} navigation_entries Navigation entries in the order commands are offered.
     *
     * @returns {{searchable_text: string, command: Object}[]} One item per entry, in the same order.
     */
    function crb_build_searchable_commands(navigation_entries) {
        return navigation_entries.map(function (navigation_entry) {
            return {
                searchable_text: crb_normalize_search_text(navigation_entry.label + ' ' + navigation_entry.search_terms.join(' ')),
                command: {
                    name: navigation_entry.command_id,
                    label: navigation_entry.label,
                    // The palette still applies its own matching to offered commands, it needs the terms too
                    keywords: navigation_entry.search_terms,
                    category: 'view',
                    callback: function (palette_controls) {
                        palette_controls.close();
                        crb_navigate_to(navigation_entry.destination_url);
                    }
                }
            };
        });
    }

    /**
     * Brings a text to the form in which typed text and command texts are compared.
     *
     * Hyphens are treated as whitespace, as the palette itself does, so that for instance
     * "logged in" finds "logged-in".
     *
     * @param {string} text The text to normalize.
     *
     * @returns {string} The text in lower case, with every run of whitespace and hyphens replaced
     *          by a single space and without leading and trailing whitespace.
     */
    function crb_normalize_search_text(text) {
        return text.toLowerCase().replace(/[\s-]+/g, ' ').trim();
    }

    /**
     * Opens the destination of a navigation command.
     *
     * A destination that differs from the current address by its fragment only does not make the
     * browser load the page, while WP Cerber admin pages act on the fragment once, when they are
     * loaded. Such a destination is therefore reloaded, so the setting it points to is revealed
     * the same way as when the command is chosen on any other page.
     *
     * @param {string} destination_url Absolute URL of the destination.
     *
     * @returns {void}
     */
    function crb_navigate_to(destination_url) {
        const destination = new URL(destination_url, window.location.href);
        const current = window.location;

        const is_same_document = destination.origin === current.origin
            && destination.pathname === current.pathname
            && destination.search === current.search;

        window.location.href = destination.href;

        if (is_same_document) {
            window.location.reload();
        }
    }
})(window.wp, window.crb_command_palette);
