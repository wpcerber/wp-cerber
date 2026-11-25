<?php
/*
	Copyright (C) 2015-26 CERBER TECH INC., https://wpcerber.com

    Licensed under the GNU GPL.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/*

*========================================================================*
|                                                                        |
|	       ATTENTION!  Do not change or edit this file!                  |
|                                                                        |
*========================================================================*

*/

/*
 * Navigation to WP Cerber admin locations from the native WordPress Command Palette.
 *
 * The integration has two layers bound by one data shape, the navigation entry:
 *
 *   array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}
 *
 * Entry sources discover locations and describe each one as a navigation entry. The registration
 * layer hands the entries to the palette and knows nothing about where an entry comes from.
 * A new source is one more function returning navigation entries, listed in
 * crb_cmd_palette_get_entries(). Sources build their entries with crb_cmd_palette_build_entry()
 * and their destinations with crb_cmd_palette_get_tab_url(), which keeps labels and destination
 * checks uniform across sources.
 */

if ( ! defined( 'WPINC' ) || ! defined( 'CERBER_VER' ) ) {
	exit;
}

// Namespace of every command ID
const CRB_CMD_PALETTE_ID_NAMESPACE = 'wp-cerber';

/**
 * Curated list of stop words: search queries too generic to offer WP Cerber commands for.
 *
 * The Command Palette is shared with WordPress and other plugins. When the whole text typed
 * into the palette equals one of these entries, WP Cerber offers no commands, so that a generic
 * search is not flooded with WP Cerber settings. The rule is an exact match of the entire query:
 * a query that merely contains a stop word, such as "login page", is searched normally, and so
 * is a longer word such as "pages" unless it is listed itself.
 *
 * Entries are compared after the same normalization as any typed text: letter case is ignored,
 * whitespace and hyphens are treated alike. Keep entries in lower case. The list is English
 * only and is not translated.
 */
const CRB_CMD_PALETTE_STOP_WORDS = array(

	// The label prefix, it occurs in every command. The entry for wp is kept on purpose,
	// although the minimum query length alone already rules that query out.
	'wp',
	'cerber',
	'wp cerber',

	// Generic WordPress admin terms
	'wordpress',
	'site',
	'page',
	'pages',
	'post',
	'posts',
	'user',
	'users',
	'plugin',
	'plugins',
	'setting',
	'settings',

	// Function words that occur in many setting titles. Shorter ones need no entry, see CRB_CMD_PALETTE_MIN_QUERY_LENGTH.
	'all',
	'for',
	'not',
	'the',
	'use',

	// The title of the Help tab. Every WP Cerber admin page has that tab, and no command leads to it.
	'help',
);

/**
 * Minimum length of a search query, in characters, for WP Cerber commands to be offered.
 *
 * A shorter query occurs in too many labels to be a meaningful search. The length is measured
 * on the typed text after the normalization used for matching, and in characters, not bytes,
 * so a query in any script is measured the same way.
 */
const CRB_CMD_PALETTE_MIN_QUERY_LENGTH = 3;

// Handle of the script that WordPress core enqueues to run the Command Palette on an admin screen
const CRB_CMD_PALETTE_CORE_SCRIPT = 'wp-core-commands';

// Action of the admin-ajax request that delivers the navigation entries on demand
const CRB_CMD_PALETTE_AJAX_ACTION = 'cerber_cmd_palette_entries';

// Nonce action of that request
const CRB_CMD_PALETTE_NONCE_ACTION = 'crb-cmd-palette';

// WordPress core enqueues the Command Palette at the default priority, the check for it must run later
add_action( 'admin_enqueue_scripts', 'crb_cmd_palette_enqueue_assets', 20 );

add_action( 'wp_ajax_' . CRB_CMD_PALETTE_AJAX_ACTION, 'crb_cmd_palette_send_entries' );

/**
 * Registers WP Cerber navigation commands in the WordPress Command Palette on the current admin screen.
 *
 * Does nothing unless the current user can manage WP Cerber and WordPress core itself has
 * enqueued the Command Palette for the screen. Relying on what core enqueued, instead of on a
 * WordPress version, leaves installations and screens without the palette untouched and never
 * loads the palette scripts where core does not.
 *
 * Does nothing either while a main Cerber.Hub website is switched to managing a remote website,
 * see nexus_is_remote_context(). In that state every WP Cerber admin page displays the remote
 * website, while navigation entries describe the local one, so a command would open a page of
 * the remote website that may not match its label. Offering no commands at all on any admin
 * screen in that state is a deliberate trade-off of the current implementation.
 *
 * The navigation entries are delivered to the browser in one of two modes:
 *
 * - Inline: when the site-wide wp_palette_reduce setting is enabled and the screen is not a
 *   WP Cerber admin page, only WP Cerber tab commands are offered. Their entries are cheap to
 *   build, need no settings registry, and are printed into the page.
 * - On demand: in any other case no entry is built while the page is printed. The script
 *   requests the complete entry list once, when the palette is first searched on the page,
 *   see crb_cmd_palette_send_entries(). Most page views never open the palette.
 *
 * The setting does not affect WordPress core or other plugins' commands.
 *
 * The configuration is passed to the browser as a JSON literal assigned to the
 * crb_command_palette JavaScript variable, which assets/command-palette.js consumes. It is an
 * object with the stop_words and min_query_length members, and either the entries member,
 * a list of navigation entries, in the inline mode, or the entries_request member, an object
 * {url: string, action: string, nonce: string}, in the on-demand mode. That script offers a
 * command only when the text typed into the palette occurs literally in the label or in a
 * search term of its entry. It offers none when the text is shorter than
 * CRB_CMD_PALETTE_MIN_QUERY_LENGTH or equals a stop word, see CRB_CMD_PALETTE_STOP_WORDS.
 *
 * @return void
 *
 * @since 10.0.1
 */
function crb_cmd_palette_enqueue_assets(): void {
	if ( ! cerber_user_can_manage() ) {
		return;
	}

	if ( ! wp_script_is( CRB_CMD_PALETTE_CORE_SCRIPT, 'enqueued' ) ) {
		return;
	}

	// Navigation entries describe the local website, they are not valid for a remote one

	if ( nexus_is_remote_context() ) {
		return;
	}

	$palette_config = array(
		'stop_words'       => CRB_CMD_PALETTE_STOP_WORDS,
		'min_query_length' => CRB_CMD_PALETTE_MIN_QUERY_LENGTH,
	);

	// Restricted mode on other admin screens: only the tab entries, inline, no request is ever made

	if ( crb_get_settings( 'wp_palette_reduce' ) && ! cerber_is_admin_page() ) {
		$tab_entries = crb_cmd_palette_get_tab_entries();

		if ( ! $tab_entries ) {
			return;
		}

		$palette_config['entries'] = $tab_entries;
	}
	else {

		// The relative URL is the one WordPress core gives its own admin scripts. It always has
		// the origin of the admin screen, so the request carries the authentication cookies.

		$palette_config['entries_request'] = array(
			'url'    => admin_url( 'admin-ajax.php', 'relative' ),
			'action' => CRB_CMD_PALETTE_AJAX_ACTION,
			'nonce'  => crb_create_nonce( CRB_CMD_PALETTE_NONCE_ACTION ),
		);
	}

	wp_enqueue_script( 'crb_command_palette', CRB_Globals::assets_url( 'command-palette.js' ), array( 'wp-commands', 'wp-data', 'wp-element' ), CERBER_VER, true );

	// The flags keep the literal safe inside a script element whatever the translated labels contain

	$palette_config_json = wp_json_encode( $palette_config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES );

	if ( ! $palette_config_json ) {
		return;
	}

	wp_add_inline_script( 'crb_command_palette', 'var crb_command_palette = ' . $palette_config_json . ';', 'before' );
}

/**
 * Sends the complete list of navigation entries in response to the admin-ajax request that
 * assets/command-palette.js makes when the palette is first searched on a page.
 *
 * The request is a POST request with the action field set to CRB_CMD_PALETTE_AJAX_ACTION and the
 * ajax_nonce field holding a nonce created for CRB_CMD_PALETTE_NONCE_ACTION, see
 * crb_cmd_palette_enqueue_assets(). The response does not depend on the screen the request was
 * made from: the screen chooses on its own whether it needs the request at all.
 *
 * The request runs in the WordPress admin context, so the entries come in the language of the
 * WP Cerber admin UI, as they would if they were built while the page was printed.
 *
 * Responses, each of them terminates the request:
 *
 * - Invalid or expired nonce: HTTP status 403 with the body -1, as check_ajax_referer() responds.
 * - A user who cannot manage WP Cerber, or a main Cerber.Hub website that manages a remote
 *   website, see nexus_is_remote_context(): HTTP status 403 with
 *   {success: false, data: string}, the data being a reason in English.
 * - Otherwise: HTTP status 200 with {success: true, data: {entries: navigation entry[]}}. The
 *   list is the one crb_cmd_palette_get_entries() returns and may be empty.
 *
 * @return void Never returns.
 *
 * @since 10.0.2
 */
function crb_cmd_palette_send_entries(): void {
	check_ajax_referer( CRB_CMD_PALETTE_NONCE_ACTION, 'ajax_nonce' );

	if ( ! cerber_user_can_manage() ) {
		wp_send_json_error( 'Access denied', 403 );
	}

	// The browser does not send the request in that state, the check is defense in depth

	if ( nexus_is_remote_context() ) {
		wp_send_json_error( 'Not available while a remote website is managed', 403 );
	}

	// The response is not embedded in a page, still the flags are kept as for the inline literal.
	// Unescaped Unicode makes the response of a non-English admin UI smaller.

	wp_send_json_success(
		array( 'entries' => crb_cmd_palette_get_entries() ),
		200,
		JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
	);
}

/**
 * Collects the navigation entries of all entry sources for the current request.
 *
 * Entries reflect the effective configuration of the current request: the language of the
 * current user, the installed WordPress version, the license, the registered add-ons, the
 * stored settings and role policies, and the set of user roles.
 * Command IDs are unique in the returned list. When two entries claim the same command ID,
 * the first one is kept.
 *
 * @return array<int,array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}>
 *         Navigation entries, empty when no location is available.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_entries(): array {

	// Every entry source is listed here.
	// Tabs go first: they are the broadest locations, and matching commands are offered in this order

	$source_entries = array_merge(
		crb_cmd_palette_get_tab_entries(),
		crb_cmd_palette_get_geo_rule_entries(),
		crb_cmd_palette_get_log_filter_entries(),
		crb_cmd_palette_get_setting_entries(),
		crb_cmd_palette_get_role_policy_entries()
	);

	// Enforce unique command IDs

	$unique_entries = array();

	foreach ( $source_entries as $navigation_entry ) {
		if ( ! isset( $unique_entries[ $navigation_entry['command_id'] ] ) ) {
			$unique_entries[ $navigation_entry['command_id'] ] = $navigation_entry;
		}
	}

	return array_values( $unique_entries );
}

/**
 * Entry source: builds one navigation entry per tab of every WP Cerber admin page.
 *
 * The tabs are the ones declared for the pages: by crb_get_admin_ui_config(), by
 * nexus_get_admin_tabs() for the Cerber.Hub page, and by CRB_Addons::get_admin_ui() for the
 * add-ons page. A tab is left out when its admin page is not accessible or does not offer it,
 * see crb_cmd_palette_get_tab_url(). The Help tab of the admin pages is not declared among the
 * tabs of any page, so it gets no entry.
 *
 * The label of an entry is the title the page has in the WordPress admin menu, see
 * crb_get_admin_page_menu_title(), followed by the title of the tab. WordPress core builds its
 * own commands for admin pages from the same menu titles. A tab titled like its page is named
 * once. The entry of the first tab of a page and the command of WordPress core for that page
 * lead to the same location, such duplicates are accepted.
 *
 * Tab titles are taken as declared. The tab_filter callbacks of the admin UI configuration are
 * not invoked: they add counters to the titles and run database queries, which only the page
 * itself needs.
 *
 * @return array<int,array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}>
 *         Navigation entries of admin page tabs.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_tab_entries(): array {

	// Collect the declared tabs of all admin pages, keyed by admin page ID

	$admin_page_tabs = array();

	foreach ( crb_get_admin_ui_config() as $admin_page_id => $admin_page_config ) {
		$admin_page_tabs[ $admin_page_id ] = $admin_page_config['tabs'];
	}

	$admin_page_tabs[ CRB_NEXUS_PAGE ] = nexus_get_admin_tabs();

	$addons_page_config = CRB_Addons::get_admin_ui();

	if ( $addons_page_config ) {
		$admin_page_tabs[ CRB_ADDON_PAGE ] = $addons_page_config['tabs'];
	}

	// Build an entry for every tab its page offers

	$tab_entries = array();

	foreach ( $admin_page_tabs as $admin_page_id => $page_tabs ) {
		$page_menu_title = crb_get_admin_page_menu_title( (string) $admin_page_id );
		$plain_page_title = crb_admin_ui_to_plain_text( $page_menu_title );

		foreach ( $page_tabs as $page_tab_id => $page_tab_config ) {
			$page_tab_id = (string) $page_tab_id;
			$page_tab_url = crb_cmd_palette_get_tab_url( $page_tab_id );

			if ( $page_tab_url === '' ) {
				continue;
			}

			$page_tab_title = (string) $page_tab_config[1];
			$plain_tab_title = crb_admin_ui_to_plain_text( $page_tab_title );

			// A page named like the tab itself adds nothing to the label

			$is_page_like_tab = crb_admin_ui_is_same_title( $plain_page_title, $plain_tab_title );

			// The page and the tab as one phrase: the label separates them, so a query that
			// names both, such as the page followed by the tab, would not occur in the label

			$page_tab_phrase = $is_page_like_tab ? $plain_tab_title : $plain_page_title . ' ' . $plain_tab_title;

			$tab_entries[] = crb_cmd_palette_build_entry(
				'tab/' . $page_tab_id,
				array( $is_page_like_tab ? '' : $page_menu_title, $page_tab_title ),
				$page_tab_url,
				array( $page_tab_id, $page_tab_phrase )
			);
		}
	}

	return $tab_entries;
}

// Admin page tab that displays the GEO rules
const CRB_CMD_PALETTE_GEO_RULES_TAB = 'geo';

/**
 * Entry source: builds navigation commands for the vertical GEO rule tabs.
 *
 * Uses the same translated rule titles as the Security Rules > Countries page.
 * Each command navigates to that page and opens the matching vertical tab.
 * No commands are offered when the parent admin tab is unavailable.
 *
 * @return array<int,array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}>
 *         Navigation entries for the GEO rule tabs.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_geo_rule_entries(): array {
	$page_tab_url = crb_cmd_palette_get_tab_url( CRB_CMD_PALETTE_GEO_RULES_TAB );

	if ( $page_tab_url === '' ) {
		return array();
	}

	// The admin page is derived from the tab, so the label names the page the URL leads to

	$admin_page_id = crb_determine_page( CRB_CMD_PALETTE_GEO_RULES_TAB );
	$page_menu_title = crb_get_admin_page_menu_title( $admin_page_id );
	$admin_page_config = crb_get_admin_ui_config( $admin_page_id );
	$page_tab_title = (string) ( $admin_page_config['tabs'][ CRB_CMD_PALETTE_GEO_RULES_TAB ][1] ?? '' );

	$geo_rule_entries = array();

	foreach ( cerber_geo_rule_set() as $geo_rule_id => $geo_rule_config ) {
		$geo_rule_id = (string) $geo_rule_id;
		$reveal_fragment = crb_build_reveal_fragment( array(
			CRB_FRAGMENT_TAB_KEY => crb_admin_get_vtab_id( $geo_rule_id ),
		) );

		$geo_rule_entries[] = crb_cmd_palette_build_entry(
			'geo-rule/' . $geo_rule_id,
			array( $page_menu_title, $page_tab_title, $geo_rule_config['name'] ),
			$page_tab_url . $reveal_fragment,
			array( $geo_rule_id )
		);
	}

	return $geo_rule_entries;
}

/**
 * Entry source: builds one navigation entry per predefined quick filter of the Activity and
 * Live Traffic logs.
 *
 * The quick filters are the ones the log screens display as quick navigation links, see
 * CRB_Log_Quick_Filters. The title of an entry is the title of the filter, and its destination
 * is the URL of the filter as that class defines it, so a command opens exactly what the link
 * on the log screen opens.
 *
 * The filter that selects all entries of a log gets no entry: it leads to the admin tab of the
 * log, which has an entry of its own, see crb_cmd_palette_get_tab_entries(). The personal
 * filters get entries, their destinations carry the ID of the current user or the IP address of
 * the current request, as on the log screen.
 *
 * A log screen hides its quick filters while the log has no entries at all. That is not checked
 * here on purpose: the entries are built for an empty log too, and such a command opens the
 * empty log. No entries are built for a log whose admin tab is unavailable, see
 * crb_cmd_palette_get_tab_url().
 *
 * @return array<int,array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}>
 *         Navigation entries of log quick filters.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_log_filter_entries(): array {

	// Quick filter sets keyed by the admin page tab of their log

	$log_filter_sets = array(
		CRB_Log_Quick_Filters::ACTIVITY_TAB => CRB_Log_Quick_Filters::get_activity_filters(),
		CRB_Log_Quick_Filters::TRAFFIC_TAB  => CRB_Log_Quick_Filters::get_traffic_filters(),
	);

	$log_filter_entries = array();

	foreach ( $log_filter_sets as $log_tab_id => $quick_filters ) {
		if ( crb_cmd_palette_get_tab_url( $log_tab_id ) === '' ) {
			continue;
		}

		// The admin page is derived from the tab, so the label names the page the URL leads to

		$admin_page_id = crb_determine_page( $log_tab_id );
		$page_menu_title = crb_get_admin_page_menu_title( $admin_page_id );
		$admin_page_config = crb_get_admin_ui_config( $admin_page_id );
		$log_tab_title = (string) ( $admin_page_config['tabs'][ $log_tab_id ][1] ?? '' );

		foreach ( $quick_filters as $quick_filter_id => $quick_filter ) {

			// A filter without query parameters selects everything: that is the tab itself

			if ( ! $quick_filter['query_params'] ) {
				continue;
			}

			// The log and the filter as one phrase: the label separates them, so a query that
			// names both, such as the log followed by the filter, would not occur in the label

			$log_filter_phrase = crb_admin_ui_to_plain_text( $log_tab_title . ' ' . $quick_filter['title'] );

			$log_filter_entries[] = crb_cmd_palette_build_entry(
				'log-filter/' . $log_tab_id . '/' . $quick_filter_id,
				array( $page_menu_title, $log_tab_title, $quick_filter['title'] ),
				$quick_filter['url'],
				array( (string) $quick_filter_id, $log_filter_phrase )
			);
		}
	}

	return $log_filter_entries;
}

/**
 * Entry source: builds one navigation entry per individual WP Cerber setting.
 *
 * The settings registry is traversed once. A setting gets an entry when the settings renderer
 * displays it as a row with a title on a settings screen that belongs to an admin page.
 * A setting is left out when it is unavailable in the current environment, see
 * CRB_Settings_Registry::is_field_available(), when it is rendered as a hidden input, or when
 * it has no title. A setting collapsed by an unmet enabler, see crb_is_enabler_met(), is left out
 * as well: its row is hidden on the settings screen until the enabling setting is turned on and
 * saved, so there is nothing to navigate to. The enabling setting itself keeps its entry.
 *
 * The destination of an entry is the admin tab of the setting with the URL fragment that makes
 * the admin UI scroll to the setting and highlight it. Role-based policies are not part of the
 * settings registry, their entries come from crb_cmd_palette_get_role_policy_entries().
 *
 * @return array<int,array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}>
 *         Navigation entries of settings.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_setting_entries(): array {
	$setting_entries = array();

	// Stored settings, the values of enabler fields are taken from them as the settings renderer does

	$stored_settings = crb_get_settings();

	foreach ( CRB_Settings_Registry::get_screen_ids() as $settings_screen_id ) {

		// A screen displayed on no admin page offers nothing to navigate to

		$page_tab_id = CRB_Settings_Registry::get_screen_tab_id( $settings_screen_id );
		$page_tab_url = crb_cmd_palette_get_tab_url( $page_tab_id );

		if ( $page_tab_url === '' ) {
			continue;
		}

		foreach ( CRB_Settings_Registry::get_screen_sections( $settings_screen_id ) as $section_config ) {
			$section_name = (string) ( $section_config['name'] ?? '' );
			$section_fields = $section_config['fields'] ?? array();

			foreach ( $section_fields as $setting_id => $field_config ) {
				$setting_id = (string) $setting_id;
				$setting_title = (string) ( $field_config['title'] ?? '' );

				// Leave out the settings that are not displayed as a row with a title

				if ( $setting_title === ''
				     || ( $field_config['type'] ?? '' ) === 'hidden'
				     || ! CRB_Settings_Registry::is_field_available( $setting_id, $field_config ) ) {
					continue;
				}

				// Leave out the settings whose row is collapsed in the admin UI

				if ( isset( $field_config['enabler'] )
				     && ! crb_is_enabler_met( $field_config, $stored_settings[ $field_config['enabler'][0] ] ?? false ) ) {
					continue;
				}

				// The fragment is the one crb_get_setting_link() generates for a global setting

				$reveal_fragment = crb_build_reveal_fragment( array( CRB_FRAGMENT_FLASH_KEY => CRB_WRAPPER_ID_PREFIX . 'global-' . $setting_id ) );

				$setting_entries[] = crb_cmd_palette_build_entry(
					'setting/' . $setting_id,
					array( $section_name, $setting_title ),
					$page_tab_url . $reveal_fragment,
					array( $setting_id )
				);
			}
		}
	}

	return $setting_entries;
}

// Admin page tab that displays the role policy form
const CRB_CMD_PALETTE_ROLE_POLICIES_TAB = 'role_policies';

/**
 * Entry source: builds one navigation entry per role policy of every user role.
 *
 * The role policy form displays the same set of policies once for each user role, on a vertical
 * tab of its own, so a policy is a separate location for each role. The roles and their names
 * are the ones the form lists, see crb_admin_render_role_policies(). On a multisite network
 * these are the roles of the main site, whatever site the current admin screen belongs to.
 *
 * The rule is the one used for settings: a policy gets an entry for a role when its row is
 * visible on the tab of that role. A policy is left out when it has no title, when it is a
 * heading row without a control of its own, when its row is hidden by the license, see
 * crb_is_role_policy_hidden(), and for the roles in which its row is collapsed by an unmet
 * enabler, see crb_is_enabler_met(). A visible policy gets an entry even if its control is
 * disabled for the role or grayed out as a PRO feature.
 *
 * The destination of an entry is the role policies tab with the URL fragment that makes the
 * admin UI open the vertical tab of the role, scroll to the policy and highlight it. It is the
 * fragment crb_get_setting_link() generates for a role policy.
 *
 * @return array<int,array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}>
 *         Navigation entries of role policies.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_role_policy_entries(): array {
	$page_tab_url = crb_cmd_palette_get_tab_url( CRB_CMD_PALETTE_ROLE_POLICIES_TAB );

	if ( $page_tab_url === '' ) {
		return array();
	}

	// The label starts with the title of the tab, it tells role policies from global settings

	$admin_page_config = crb_get_admin_ui_config( crb_determine_page( CRB_CMD_PALETTE_ROLE_POLICIES_TAB ) );
	$page_tab_title = (string) ( $admin_page_config['tabs'][ CRB_CMD_PALETTE_ROLE_POLICIES_TAB ][1] ?? '' );

	$policy_sections = crb_get_role_settings_config();
	$policy_entries = array();

	// On a multisite network the form is displayed in the network admin, which lists the roles
	// of the main site, while this code may run on the admin screen of any site of the network

	$form_roles = is_multisite() ? new WP_Roles( get_main_site_id() ) : wp_roles();

	foreach ( $form_roles->role_names as $role_id => $role_name ) {
		$role_id = (string) $role_id;

		// DOM IDs on the form are built from the sanitized role ID

		$role_dom_id = crb_sanitize_id( $role_id );

		if ( $role_dom_id === '' ) {
			continue;
		}

		$role_policies = cerber_get_role_policies( $role_id );

		foreach ( $policy_sections as $section_config ) {
			$section_name = (string) ( $section_config['name'] ?? '' );

			foreach ( $section_config['fields'] as $policy_id => $field_config ) {
				$policy_id = (string) $policy_id;
				$policy_title = (string) ( $field_config['title'] ?? '' );

				// Leave out the policies that are not displayed as a row with a title and a control

				if ( $policy_title === ''
				     || ( $field_config['type'] ?? '' ) === 'html'
				     || crb_is_role_policy_hidden( $policy_id ) ) {
					continue;
				}

				// Leave out the policies whose row is collapsed for this role

				if ( isset( $field_config['enabler'] )
				     && ! crb_is_enabler_met( $field_config, $role_policies[ $field_config['enabler'][0] ] ?? '' ) ) {
					continue;
				}

				// A section named like the policy itself adds nothing to the label

				$section_label_part = crb_admin_ui_is_same_title( $section_name, $policy_title ) ? '' : $section_name;

				$reveal_fragment = crb_build_reveal_fragment( array(
					CRB_FRAGMENT_TAB_KEY   => crb_admin_get_vtab_id( $role_dom_id ),
					CRB_FRAGMENT_FLASH_KEY => CRB_WRAPPER_ID_PREFIX . 'role-' . $role_dom_id . '-' . $policy_id,
				) );

				$policy_entries[] = crb_cmd_palette_build_entry(
					'role-policy/' . $role_dom_id . '/' . $policy_id,
					array( $page_tab_title, (string) $role_name, $section_label_part, $policy_title ),
					$page_tab_url . $reveal_fragment,
					array( $policy_id, $role_id )
				);
			}
		}
	}

	return $policy_entries;
}

/**
 * Builds a navigation entry, the unit the registration layer turns into a palette command.
 *
 * All entry sources must build their entries here so that command IDs share one namespace and
 * labels share one format: the title of the WP Cerber admin menu, see CRB_ADMIN_MENU_TITLE, as
 * the prefix that makes WP Cerber commands recognizable among other commands, followed by the
 * label parts from the broadest context to the location itself, for instance a section name and
 * a setting title. Label parts may contain HTML, they are converted to plain text. Empty parts
 * are skipped.
 *
 * When the WP Cerber admin interface is displayed in a language other than English, the entry
 * is searchable by the original English phrases too, for compatibility with the English
 * documentation. The English version of the label, without the prefix and with its parts
 * separated by spaces, is added to the search terms. That happens when at least one label part
 * is a translated phrase, see crb_cmd_palette_get_english_phrases(). A label part must be passed
 * exactly as the translation function returned it to be recognized. A part that is not
 * recognized is kept in the English version as it is.
 *
 * @param string $location_id Stable ID of the location, unique among all entry sources. Sources
 *                            prefix it with their own kind, for instance setting/limit.
 * @param array<int,string> $label_parts Translated label parts, ordered from the broadest context
 *                                       to the location itself.
 * @param string $destination_url Raw absolute URL the command navigates to.
 * @param array<int,string> $search_terms Additional terms a search in the palette is matched
 *                                        against, on top of the label. They are not displayed.
 *
 * @return array{command_id:string,label:string,search_terms:array<int,string>,destination_url:string}
 *         Navigation entry.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_build_entry( string $location_id, array $label_parts, string $destination_url, array $search_terms = array() ): array {
	$english_phrases = crb_cmd_palette_get_english_phrases();

	$plain_label_parts = array();
	$english_label_parts = array();
	$has_translated_part = false;

	foreach ( $label_parts as $label_part ) {
		$label_part = (string) $label_part;
		$plain_label_part = crb_admin_ui_to_plain_text( $label_part );

		if ( $plain_label_part === '' ) {
			continue;
		}

		$plain_label_parts[] = $plain_label_part;

		// The original is looked up by the part as it was translated, before any conversion

		if ( isset( $english_phrases[ $label_part ] ) ) {
			$english_label_parts[] = crb_admin_ui_to_plain_text( $english_phrases[ $label_part ] );
			$has_translated_part = true;
		}
		else {
			$english_label_parts[] = $plain_label_part;
		}
	}

	// A label that is in English already needs no English version

	if ( $has_translated_part ) {
		$search_terms[] = implode( ' ', $english_label_parts );
	}

	return array(
		'command_id'      => CRB_CMD_PALETTE_ID_NAMESPACE . '/' . $location_id,
		'label'           => CRB_ADMIN_MENU_TITLE . ': ' . implode( ' > ', $plain_label_parts ),
		'search_terms'    => array_values( $search_terms ),
		'destination_url' => $destination_url,
	);
}

/**
 * Returns the original English phrases of WP Cerber, keyed by their translations.
 *
 * The map is the reverse of the translation WordPress has loaded for the wp-cerber text domain
 * in the current request. It tells which English phrase a translated piece of the admin UI,
 * for instance a setting title, was made from. It is built on the first call and reused for
 * the rest of the PHP request.
 *
 * The map is empty when no translation is loaded, which is the case when the WP Cerber admin
 * interface is displayed in English. It is empty as well on WordPress older than 6.5, which
 * lacks the translation controller the entries are taken from.
 *
 * Of a phrase with plural forms only the singular form is taken, the one a translation request
 * without a number returns. A phrase whose translation equals the original is left out. When
 * several originals share one translation, the first one is kept.
 *
 * @return array<string,string> Original English phrases keyed by translated phrases. Both are
 *                              as the translation holds them, they may contain HTML.
 *
 * @since 10.0.2
 */
function crb_cmd_palette_get_english_phrases(): array {
	static $english_phrases = null;

	if ( $english_phrases !== null ) {
		return $english_phrases;
	}

	$english_phrases = array();

	if ( ! class_exists( 'WP_Translation_Controller' ) ) {
		return $english_phrases;
	}

	// The controller gives the entries as plain strings. The legacy interface, the entries
	// property of get_translations_for_domain(), would build an object for each of them.

	$translation_entries = WP_Translation_Controller::get_instance()->get_entries( 'wp-cerber' );

	foreach ( $translation_entries as $original_phrase => $translated_phrase ) {

		// Plural forms are separated by a NUL character, the singular form goes first

		$original_phrase = explode( "\0", (string) $original_phrase, 2 )[0];
		$translated_phrase = explode( "\0", (string) $translated_phrase, 2 )[0];

		// A translation context precedes the original, separated by an EOT character

		$context_and_phrase = explode( "\4", $original_phrase, 2 );
		$original_phrase = $context_and_phrase[1] ?? $context_and_phrase[0];

		if ( $translated_phrase === ''
		     || $translated_phrase === $original_phrase
		     || isset( $english_phrases[ $translated_phrase ] ) ) {
			continue;
		}

		$english_phrases[ $translated_phrase ] = $original_phrase;
	}

	return $english_phrases;
}

/**
 * Returns the URL of a WP Cerber admin page tab, provided the tab belongs to an admin page.
 *
 * All entry sources must build their destinations here. cerber_admin_link() silently falls back
 * to the main WP Cerber admin page for a tab it cannot place, which would produce a command that
 * leads to the wrong location. This function reports such a tab instead. It also reports a tab
 * of an admin page that is not enabled, see crb_is_admin_page_enabled(), for instance a page
 * that requires a PRO license, because WordPress denies access to such a page.
 *
 * A tab of the Cerber.Hub admin page is reported as well unless the page offers it in the
 * current Cerber.Hub mode of the website, see nexus_get_admin_tabs(). That page silently opens
 * its first tab, or the mode selection, for a tab it does not offer. It is the only admin page
 * whose set of tabs depends on the state of the website, the tabs of all other pages are fixed.
 *
 * @param string $page_tab_id Admin page tab ID.
 *
 * @return string Raw absolute URL, or an empty string when the tab belongs to no accessible
 *                admin page or the page does not offer the tab.
 *
 * @since 10.0.1
 */
function crb_cmd_palette_get_tab_url( string $page_tab_id ): string {
	if ( $page_tab_id === '' ) {
		return '';
	}

	$admin_page_id = crb_determine_page( $page_tab_id );

	if ( $admin_page_id === '' || ! crb_is_admin_page_enabled( $admin_page_id ) ) {
		return '';
	}

	// The Cerber.Hub page offers a tab only in the matching Cerber.Hub mode of the website

	if ( $admin_page_id === CRB_NEXUS_PAGE
	     && ! isset( nexus_get_admin_tabs()[ $page_tab_id ] ) ) {
		return '';
	}

	return cerber_admin_link( $page_tab_id );
}
