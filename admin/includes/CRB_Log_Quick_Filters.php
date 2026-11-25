<?php

/**
 * Definitions of the predefined quick filters of the Activity and Live Traffic logs.
 *
 * A quick filter is a named, ready-made selection of log entries, for instance "Login issues".
 * It is defined by two things: the query parameters that make a log screen display the
 * selection, and a translated title. This class is the single definition of the quick filters.
 * It only describes them. It renders nothing and knows nothing about the code that uses the
 * definitions: the log screens display them as quick navigation links, see
 * crb_build_quick_filter_nav(), and any other code may read them, for instance to offer the same
 * selections elsewhere.
 *
 * A set of quick filters is a list keyed by quick filter ID, in the order the log screen displays
 * the filters. The ID is a stable, untranslated name of the filter within its set, the same ID
 * may occur in both sets. Each definition is an array of three elements:
 *
 *   query_params  Query parameters of the filter. Added to the URL of the admin page tab of the
 *                 log, they make the log screen display the selection. Empty for the filter
 *                 that selects all entries. The value of a parameter is a scalar or a list of
 *                 scalars.
 *   title         Translated title of the filter, plain text that is not escaped for any output
 *                 context.
 *   url           Raw absolute URL of the log screen displaying the selection: the admin page
 *                 tab of the log with the query parameters of the filter. It is not escaped for
 *                 any output context. Code that only needs to lead to a filter uses this URL
 *                 and does not build one.
 *
 * The URL is derived from the query parameters when a set is built. Code that alters the query
 * parameters in its copy of a definition must not use the URL of that copy.
 *
 * The sets describe the current request. Some filters are personal: their query parameters carry
 * the ID of the current user or the IP address of the current request. Some depend on the
 * settings of the website or on the kind of the request, such a filter is absent from the set
 * when it does not apply. Titles are translated, so the sets must be obtained on or after the
 * init hook.
 *
 * ARCHITECTURAL BOUNDARY
 *
 * This class defines a curated set of user-facing quick filters, not a registry of all possible
 * log queries. Every filter it defines is displayed on its log screen and offered as a command
 * by the Command Palette, so adding a filter is an explicit UI decision. Do not add filters
 * merely to centralize or deduplicate log URLs.
 *
 * Code that leads to exactly the selection of an existing filter, with no additional criteria,
 * reuses the url of that filter instead of building its own. A link that combines the criteria
 * of a filter with others, for instance a particular user, IP address, or time range, is not a
 * quick filter and builds its own URL.
 *
 * @since 10.0.1
 */
final class CRB_Log_Quick_Filters {

	/**
	 * ID of the admin page tab that displays the Activity log
	 */
	const ACTIVITY_TAB = 'activity';

	/**
	 * ID of the admin page tab that displays the Live Traffic log
	 */
	const TRAFFIC_TAB = 'traffic';

	/**
	 * Returns the quick filters of the Activity log.
	 *
	 * The two personal filters, my_activity and my_ip, are absent when the request is a
	 * Cerber.Hub request from a main website, see nexus_is_valid_request(): the current user
	 * and the IP address of such a request do not belong to an administrator of this website.
	 *
	 * @return array<string,array{query_params:array<string,mixed>,title:string,url:string}>
	 *         Quick filter definitions keyed by quick filter ID, in the order they are displayed.
	 *
	 * @since 10.0.1
	 */
	public static function get_activity_filters(): array {
		$activity_labels = cerber_get_labels( 'activity' );

		$quick_filters = array(
			'all'               => array(
				'query_params' => array(),
				'title'        => __( 'View all', 'wp-cerber' ),
			),
			'logged_in'         => array(
				'query_params' => array( 'filter_activity' => CRB_EV_LIN ),
				'title'        => $activity_labels[ CRB_EV_LIN ],
			),
			'new_users'         => array(
				'query_params' => array( 'filter_activity' => array( 1, 2 ) ),
				'title'        => __( 'New users', 'wp-cerber' ),
			),
			'login_issues'      => array(
				'query_params' => array( 'filter_set' => 2 ),
				'title'        => __( 'Login issues', 'wp-cerber' ),
			),
			'suspicious'        => array(
				'query_params' => array( 'filter_set' => 1 ),
				'title'        => __( 'Suspicious activity', 'wp-cerber' ),
			),
			'spam_events'       => array(
				'query_params' => array( 'filter_status' => array( CRB_STS_11, CRB_STS_532, 706 ) ),
				'title'        => __( 'Spam Events', 'wp-cerber' ),
			),
			'ip_locked_out'     => array(
				'query_params' => array( 'filter_activity' => array( CRB_EV_IPL, CRB_EV_NEL ) ),
				'title'        => __( 'IP locked out', 'wp-cerber' ),
			),
			'users'             => array(
				'query_params' => array( 'filter_user' => '*' ),
				'title'        => __( 'Users', 'wp-cerber' ),
			),
			'non_authenticated' => array(
				'query_params' => array( 'filter_user' => 0 ),
				'title'        => __( 'Non-authenticated', 'wp-cerber' ),
			),
		);

		// Personal filters make no sense for a request that comes from a main Cerber.Hub website

		if ( ! nexus_is_valid_request() ) {
			$quick_filters['my_activity'] = array(
				'query_params' => array( 'filter_user' => get_current_user_id() ),
				'title'        => __( 'My activity', 'wp-cerber' ),
			);
			$quick_filters['my_ip'] = array(
				'query_params' => array( 'filter_ip' => cerber_get_remote_ip() ),
				'title'        => __( 'My IP', 'wp-cerber' ),
			);
		}

		return self::add_filter_urls( $quick_filters, self::ACTIVITY_TAB );
	}

	/**
	 * Returns the quick filters of the Live Traffic log.
	 *
	 * The long_requests filter selects the requests processed longer than the threshold set in
	 * the Traffic Inspector settings. It is absent when no threshold is set.
	 *
	 * @return array<string,array{query_params:array<string,mixed>,title:string,url:string}>
	 *         Quick filter definitions keyed by quick filter ID, in the order they are displayed.
	 *
	 * @since 10.0.1
	 */
	public static function get_traffic_filters(): array {
		$quick_filters = array(
			'all'               => array(
				'query_params' => array(),
				'title'        => __( 'View all', 'wp-cerber' ),
			),
			'suspicious'        => array(
				'query_params' => array( 'filter_set' => 1 ),
				'title'        => __( 'Suspicious requests', 'wp-cerber' ),
			),
			'errors'            => array(
				'query_params' => array( 'filter_http_code' => 399, 'filter_http_code_mode' => 'GT' ),
				'title'        => __( 'Errors', 'wp-cerber' ),
			),
			'users'             => array(
				'query_params' => array( 'filter_user' => '*' ),
				'title'        => __( 'Users', 'wp-cerber' ),
			),
			'non_authenticated' => array(
				'query_params' => array( 'filter_user' => 0 ),
				'title'        => __( 'Non-authenticated', 'wp-cerber' ),
			),
			'form_submissions'  => array(
				'query_params' => array( 'filter_method' => 'POST', 'filter_wp_type' => 520, 'filter_wp_type_mode' => 'GT' ),
				'title'        => __( 'Form submissions', 'wp-cerber' ),
			),
			'not_found'         => array(
				'query_params' => array( 'filter_http_code' => 404 ),
				'title'        => __( 'Page Not Found', 'wp-cerber' ),
			),
			'rest_api'          => array(
				'query_params' => array( 'filter_wp_type' => 520 ),
				'title'        => 'REST API',
			),
			'xml_rpc'           => array(
				'query_params' => array( 'filter_wp_type' => 515 ),
				'title'        => 'XML-RPC',
			),
			'my_requests'       => array(
				'query_params' => array( 'filter_user' => get_current_user_id() ),
				'title'        => __( 'My requests', 'wp-cerber' ),
			),
			'my_ip'             => array(
				'query_params' => array( 'filter_ip' => cerber_get_remote_ip() ),
				'title'        => __( 'My IP', 'wp-cerber' ),
			),
		);

		// Requests processed longer than the threshold, if the website has one

		$processing_threshold = (int) crb_get_settings( 'tithreshold' );

		if ( $processing_threshold ) {
			$quick_filters['long_requests'] = array(
				'query_params' => array( 'filter_processing' => $processing_threshold ),
				/* translators: %d is the processing time threshold in milliseconds. */
				'title'        => sprintf( __( 'Longer than %d ms', 'wp-cerber' ), $processing_threshold ),
			);
		}

		return self::add_filter_urls( $quick_filters, self::TRAFFIC_TAB );
	}

	/**
	 * Adds the URL of the log screen to every quick filter definition of a set.
	 *
	 * This is the single place the URL of a quick filter is generated.
	 *
	 * @param array<string,array{query_params:array<string,mixed>,title:string}> $quick_filters
	 *        Quick filter definitions keyed by quick filter ID.
	 * @param string $log_tab ID of the admin page tab of the log the filters belong to.
	 *
	 * @return array<string,array{query_params:array<string,mixed>,title:string,url:string}>
	 *         The same definitions in the same order, each with its url element.
	 *
	 * @since 10.0.1
	 */
	private static function add_filter_urls( array $quick_filters, string $log_tab ): array {
		foreach ( $quick_filters as $quick_filter_id => $quick_filter ) {
			$quick_filters[ $quick_filter_id ]['url'] = cerber_admin_link( $log_tab, $quick_filter['query_params'] );
		}

		return $quick_filters;
	}
}
