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
const CERBER_PIN_LENGTH = 4;
const CERBER_PIN_EXPIRES = 15;

final class CRB_2FA {
	static $token = '';
	static $user_set = null;

	/**
	 * The maximum number of new 2FA challenges per account in a rolling 60-minute window.
	 */
	private const CHALLENGE_LIMIT_HOUR = 5;

	/**
	 * The maximum number of new 2FA challenges per account in a rolling 24-hour window.
	 */
	private const CHALLENGE_LIMIT_DAY = 10;

	/**
	 * The short rolling window for counting new 2FA challenges, in seconds.
	 */
	private const CHALLENGE_WINDOW_HOUR = 3600;

	/**
	 * The long rolling window for counting new 2FA challenges, in seconds.
	 */
	private const CHALLENGE_WINDOW_DAY = 86400;

	/**
	 * Duration of the account lock established after a challenge limit is exceeded, in seconds.
	 */
	private const LOCK_DURATION = 86400;

	/**
	 * The maximum number of incorrect PINs over the lifetime of a pending 2FA challenge.
	 */
	private const PIN_FAILURE_BUDGET = 6;

	/**
	 * Enforce 2FA for a user based on the plugin settings
	 *
	 * Terminates the current request: after initiating a new 2FA challenge (redirect to the
	 * 2FA page), and when the new sign-in is denied because of an active account lock,
	 * an exceeded challenge limit, or a failure to set up a counted challenge
	 * (see abort_new_login()).
	 *
	 * @param string $login User login
	 * @param WP_User $user
	 *
	 * @return bool|WP_Error
	 */
	static function main_controller( $login, $user ) {
		static $done = false;

		if ( $done ) {
			return 0;
		}

		$done = true;

		if ( ( $user instanceof WP_User ) && ! empty( $user->ID )
		     && crb_is_auth_locked( $user->ID ) ) {

			// An active account lock denies any new sign-in, including the ones that skip the login form
			// or 2FA (remembered devices, allowed IPs, programmatic sign-ins via wp_set_auth_cookie()).

			cerber_log( CRB_EV_LDN, (string) $login, $user->ID, 543 );
			self::abort_new_login( $user->ID );
		}

		if ( crb_acl_is_allowed() ) {
			return 6;
		}

		if ( ( ! $user instanceof WP_User ) || empty( $user->ID ) ) {
			return new WP_Error( 'no-user', 'Invalid user data' );
		}

		self::remove_expired_cookies( $user->ID );

		$user_mode = self::get_user_meta_data( 'tfm', $user->ID );

        if ( $user_mode === 2 ) {
	        return 7;
		}

		if ( ( $coo = self::get_user_meta_data( 'tf_remember', $user->ID ) )
		     && self::get_user_days( $user->ID ) ) {

            // Check for remembered devices

			foreach ( $coo as $coo_name => $coo_data ) {
				if ( $coo_data[1] > time()
				     && cerber_get_cookie( $coo_name ) == $coo_data[0] ) {

					return 8;
				}
			}

		}

		if ( $user_mode == 1 ) {
			$go = true;
		}
		else {

			$u_roles = null;

			if ( ! empty( $user->roles ) ) {
				$u_roles = $user->roles;
			}
			else { // a backup way
				$data = get_userdata( $user->ID );
				if ( ! empty( $data->roles ) ) {
					$u_roles = $data->roles;
				}
			}

			if ( empty( $u_roles ) ) {
				return new WP_Error( 'no-roles', 'No roles found for the user #' . $user->ID );
			}

			if ( $go = self::check_role_policies( $user->ID, $u_roles ) ) {
				CRB_Globals::set_ctrl_setting( $go );
			}

		}

		if ( ! $go ) {
			return 9;
		}

		// This user must complete 2FA. Admission control: evaluate the account limits before any PIN exists.

		if ( ! self::enforce_limits( $user->ID ) ) {
			self::abort_new_login( $user->ID );
		}

		$login = (string) $login;

		// Count the admitted challenge before a usable PIN exists, so a logging failure cannot leave an uncounted challenge

		if ( ! cerber_log( CRB_EV_2FA, $login, $user->ID ) ) {
			cerber_error_log( 'Unable to record the 2FA challenge for the user #' . $user->ID . ' | RID: ' . get_wp_cerber()->getRequestID(), '2FA' );
			self::abort_new_login( $user->ID );
		}

		// A failed challenge setup must not let the new session continue without 2FA

		$ret = self::initiate_2fa( $user, $login );

		if ( crb_is_wp_error( $ret ) ) {
			cerber_error_log( $ret->get_error_message() . ' | RID: ' . get_wp_cerber()->getRequestID(), '2FA' );
			self::abort_new_login( $user->ID );
		}

		crb_sessions_update( $user->ID, self::get_session_token_hash(), array( 'mfa_status' => 1 ) );

		$home = cerber_get_home_url();

		if ( 2 < substr_count( $home, '/' ) ) {
            // Home page URL includes a subfolder. Make sure it contains trailing slash as well. Improves web servers compatibility.
			$home .= '/';
		}

		crb_safe_redirect( $home );
		exit;

	}

	/**
     * Check if 2FA must be enforced.
     *
     * @param int $user_id
	 * @param string[] $roles
	 *
	 * @return string|bool Non-empty string if the given user must complete 2FA, false otherwise
	 */
	private static function check_role_policies( $user_id, $roles ) {

		foreach ( $roles as $role ) {

			$policies = cerber_get_role_policies( $role );

			if ( empty( $policies['2famode'] )
			     || ( $policies['2famode'] == 2 && ! lab_lab() ) ) {
				continue;
			}
            elseif ( $policies['2famode'] == 1 ) {
				return '2famode';
			}

			if ( $history = self::get_user_meta_data( '2fa_history', $user_id ) ) {
				if ( ( $logins = crb_array_get( $policies, '2falogins' ) )
				     && ( $history[0] >= $logins ) ) {
					return '2falogins';
				}
				if ( ( $days = crb_array_get( $policies, '2fadays' ) )
				     && ( ( time() - $history[1] ) > $days * 24 * 3600 ) ) {
					return '2fadays';
				}
			}

			if ( $last_login = self::get_user_meta_data( 'last_login', $user_id ) ) {
				if ( crb_array_get( $policies, '2fanewip' ) ) {
					if ( $last_login['ip'] != cerber_get_remote_ip() ) {
						return '2fanewip';
					}
				}
				if ( crb_array_get( $policies, '2fanewnet4' ) ) {
					if ( cerber_get_subnet_ipv4( $last_login['ip'] ) != cerber_get_subnet_ipv4( cerber_get_remote_ip() ) ) {
						return '2fanewnet4';
					}
				}
				if ( crb_array_get( $policies, '2fanewua' ) ) {
					if ( $last_login['ua'] != sha1( crb_array_get( $_SERVER, 'HTTP_USER_AGENT', '' ) ) ) {
						return '2fanewua';
					}
				}
			}

			if ( $limit = crb_array_get( $policies, '2fasessions' ) ) {
				if ( $limit < crb_sessions_get_num( $user_id ) ) {
					return '2fasessions';
				}
			}

			if ( $last_login ) {
				if ( crb_array_get( $policies, '2fanewcountry' ) ) {
					if ( lab_get_country( $last_login['ip'], false ) != lab_get_country( cerber_get_remote_ip(), false ) ) {
						return '2fanewcountry';
					}
				}
			}
		}

		return false;
	}

	/**
	 * Enforces the per-account limits for initiating new 2FA challenges.
	 *
	 * Counts CRB_EV_2FA events of the account within a rolling 60-minute window and a rolling
	 * 24-hour window. If either limit is reached, locks new sign-ins of the account for 24 hours,
	 * logs the security event (CRB_EV_ALK with status 543), and sends an email notification
	 * to the user. The lock is persisted first: a logging or email failure does not undo it.
	 *
	 * Fails closed: if the events cannot be counted or the lock cannot be persisted, initiation
	 * is denied and the failure is reported to the diagnostic log.
	 *
	 * Does not terminate the current login session or affect existing sessions.
	 * The caller must abort the current login if initiation is denied.
	 *
	 * @param int $user_id WordPress user ID.
	 *
	 * @return bool True if initiation is allowed, false if denied or the check fails.
	 *
	 * @since 9.9.6
	 */
	private static function enforce_limits( int $user_id ): bool {
		$now = time();

		// Fetch the challenges of the longest window; a failed count is never treated as zero

		$stamps_result = self::get_challenge_stamps( $user_id, $now - self::CHALLENGE_WINDOW_DAY );

		if ( $stamps_result->has_errors() ) {
			cerber_error_log( 'Unable to count 2FA challenges of the user #' . $user_id . ': ' . $stamps_result->get_error_message(), '2FA' );

			return false;
		}

		if ( ! self::is_challenge_limit_exceeded( $stamps_result->get_results( array() ), $now ) ) {
			return true;
		}

		// Persist the lock first: the steps after it are best effort and must not undo it

		$lock = array(
			'locked_at' => $now,
			'expires'   => $now + self::LOCK_DURATION,
			'status'    => 543,
			'notified'  => false,
		);

		if ( ! update_user_meta( $user_id, CERBER_AUTHBLOCK, $lock ) ) {
			cerber_error_log( 'Unable to save the account lock of the user #' . $user_id, '2FA' );

			return false;
		}

		if ( ! cerber_log( CRB_EV_ALK, '', $user_id, 543 ) ) {
			cerber_error_log( 'Unable to record the account lock event of the user #' . $user_id, '2FA' );
		}

		self::notify_account_lock( $user_id, $lock );

		return false;
	}

	/**
	 * Returns the timestamps of the 2FA challenges initiated for the account after the given moment.
	 *
	 * Reads CRB_EV_2FA events from the Activity Log. Performs a database query.
	 *
	 * @param int $user_id WordPress user ID.
	 * @param int $since Unix timestamp; only challenges initiated after this moment are returned.
	 *
	 * @return Revalt<array<int,mixed>> Timestamps of the challenges as returned by the database, or database errors.
	 *
	 * @since 9.9.6
	 */
	private static function get_challenge_stamps( int $user_id, int $since ): Revalt {
		// The limits rely on get_log() being uncached: a cached read would undercount recent challenges.
		$log_result = CRB_Activity::get_log( array(
			'activity'    => array( CRB_EV_2FA ),
			'user_id'     => $user_id,
			'stamp_after' => $since,
			'columns'     => array( 'stamp' ),
		) );

		if ( $log_result->has_errors() ) {
			return $log_result;
		}

		$challenge_stamps = array();

		foreach ( $log_result->get_results( array() ) as $log_row ) {
			$challenge_stamps[] = $log_row->stamp;
		}

		return new Revalt( $challenge_stamps );
	}

	/**
	 * Decides whether a new 2FA challenge would exceed the per-account limits.
	 *
	 * A new challenge is denied when the number of earlier challenges already reaches a limit:
	 * CHALLENGE_LIMIT_HOUR within the last 60 minutes or CHALLENGE_LIMIT_DAY within the last
	 * 24 hours. Thus, the sixth challenge in an hour or the eleventh one in a day is denied.
	 * Pure function, no side effects.
	 *
	 * @param array<int,mixed> $challenge_stamps Unix timestamps of earlier challenges (int, float, or numeric string).
	 * @param int $now Current Unix timestamp.
	 *
	 * @return bool True if the new challenge must be denied, false otherwise.
	 *
	 * @since 9.9.6
	 */
	private static function is_challenge_limit_exceeded( array $challenge_stamps, int $now ): bool {
		$hour_count = 0;
		$day_count = 0;

		foreach ( $challenge_stamps as $challenge_stamp ) {
			$stamp = (float) $challenge_stamp;

			if ( $stamp > $now - self::CHALLENGE_WINDOW_DAY ) {
				$day_count ++;
			}

			if ( $stamp > $now - self::CHALLENGE_WINDOW_HOUR ) {
				$hour_count ++;
			}
		}

		return $hour_count >= self::CHALLENGE_LIMIT_HOUR
		       || $day_count >= self::CHALLENGE_LIMIT_DAY;
	}

	/**
	 * Sends the security notification about a newly established account lock to the account owner.
	 *
	 * Makes a single delivery attempt to the primary email address of the account (WP_User::user_email),
	 * not to the alternate address used to deliver 2FA PINs. It is called only when a new lock
	 * is established, so subsequent denied sign-ins do not produce more emails. On success, the lock
	 * record is marked as notified. A delivery failure is reported to the diagnostic log and does
	 * not affect the lock.
	 *
	 * @param int $user_id WordPress user ID.
	 * @param array{locked_at:int,expires:int,status:int,notified:bool} $lock The lock record that has just been saved.
	 *
	 * @return void
	 *
	 * @since 9.9.6
	 */
	private static function notify_account_lock( int $user_id, array $lock ): void {

		$user_data = get_userdata( $user_id );

		if ( ! $user_data || ! is_email( $user_data->user_email ) ) {
			cerber_error_log( 'Unable to send the account lock notification to the user #' . $user_id . ': no valid email address', '2FA' );

			return;
		}

		// Compose the message: a compromise is possible, but it is not confirmed

		$subject = __( 'New sign-ins to your account are temporarily blocked', 'wp-cerber' );

		$body = array();
		$body[] = __( 'We have detected an unusual number of two-factor authentication requests for your account. Each of them was made after your password had been entered correctly.', 'wp-cerber' );
		/* translators: %s is the date and time when the restriction ends. */
		$body[] = sprintf( __( 'To protect your account, new sign-ins are blocked for 24 hours, until %s. Your active sessions are not affected.', 'wp-cerber' ), cerber_date( $lock['expires'], false ) );
		/* translators: %s is the URL of the password reset page. */
		$body[] = sprintf( __( 'If you did not try to sign in, your password may be compromised. We recommend resetting your password: %s', 'wp-cerber' ), wp_lostpassword_url() );
		$body[] = __( 'Changing the password does not remove this temporary restriction.', 'wp-cerber' );
		/* translators: %s is the user login name. */
		$body[] = sprintf( __( 'Login: %s', 'wp-cerber' ), $user_data->user_login );

		// Deliver it to the primary email address of the account

		$user_name = crb_sanitize_mail_display_name( trim( $user_data->user_firstname . ' ' . $user_data->user_lastname ) );
		$recipient = $user_name ? '"' . $user_name . '" <' . $user_data->user_email . '>' : $user_data->user_email;

		$sent = CRB_Messaging::send( '2fa', array(
			'subj' => $subject,
			'text' => implode( "\n\n", $body ),
		), array( 'email' => 1, 'pushbullet' => 0 ), true, array( 'email_recipients' => array( $recipient ) ) );

		if ( ! $sent ) {
			cerber_error_log( 'Unable to send the account lock notification to the user #' . $user_id, '2FA' );

			return;
		}

		// Keep the lock record self-describing for diagnostics; a failure here is not critical

		$lock['notified'] = true;
		update_user_meta( $user_id, CERBER_AUTHBLOCK, $lock );
	}

	/**
	 * Abort a newly initiated login after a 2FA security restriction.
	 *
	 * Destroys only the newly created WordPress session token,
	 * clears authentication cookies, and terminates the request.
	 * Previously established server-side sessions remain intact.
	 *
	 * The new session token is the one issued by wp_set_auth_cookie() in the current request.
	 * The session of the incoming browser cookie is not touched. The request is redirected to
	 * the login page, which honors the WP Cerber custom login URL. The redirect URL carries the
	 * cerber_auth_abort query parameter: 'locked' if the account lock is active, 'failed' otherwise.
	 * If the new session token cannot be invalidated, the request is terminated with an error
	 * response instead of the redirect.
	 *
	 * @param int $user_id ID of the user being authenticated.
	 *
	 * @return void This method terminates the request.
	 *
	 * @since 9.9.6
	 */
	private static function abort_new_login( int $user_id ): void {

		// Invalidate the new session server-side: clearing cookies does not stop a client that ignores the response cookies

		if ( self::$token ) {
			$session_manager = WP_Session_Tokens::get_instance( $user_id );
			$session_manager->destroy( self::$token );

			if ( $session_manager->verify( self::$token ) ) {
				cerber_error_log( 'Unable to destroy the new session of the user #' . $user_id, '2FA' );
				wp_clear_auth_cookie();
				wp_die( 'Unable to complete the authentication.', 'Authentication error', array( 'response' => 403 ) );
			}
		}
		else {
			cerber_error_log( 'Unable to identify the new authentication session token of the user #' . $user_id, '2FA' );
		}

		wp_clear_auth_cookie();

		// Redirect to the login page with a static, non-account-specific explanation

		$abort_reason = crb_is_auth_locked( $user_id ) ? 'locked' : 'failed';
		$login_url = add_query_arg( 'cerber_auth_abort', $abort_reason, wp_login_url() );

		if ( crb_safe_redirect( $login_url ) ) {
			exit;
		}

		wp_die( 'Unable to redirect to the login page.', 'Authentication error', array( 'response' => 403 ) );
	}

	/**
     * Return user's meta data handled by WP Cerber
	 *
	 * @param string $field
	 * @param integer $user_id
	 *
	 * @return false|mixed
     *
     * @since 9.6.1
	 */
	private static function get_user_meta_data( $field, $user_id ) {
		static $pro = array( 'tfm', 'tf_remember', 'tfremember', '2fa_history', 'last_login' );

		if ( in_array( $field, $pro )
             && ! lab_lab() ) {
			return false;
		}

		if ( ! self::$user_set ) {
			self::$user_set = cerber_get_set( CRB_USER_SET, $user_id );
		}

		return crb_array_get( self::$user_set, $field );
    }

	/**
	 * Initiate 2FA process
	 *
	 * Creates the pending 2FA challenge record of the new session with a zero lifetime PIN
	 * failure counter (total_attempts), then generates and sends the PIN. The record is saved
	 * before the PIN, so a usable PIN never exists without an initialized failure counter.
	 *
	 * @param WP_User $user
	 * @param string $login
	 *
	 * @return bool|string|WP_Error The PIN on success, WP_Error if the challenge cannot be created.
	 */
	private static function initiate_2fa( $user, $login = '' ) {

		$data = array(
			'login'          => $login,
			'to'             => cerber_2fa_get_redirect_to( $user ),
			'ajax'           => cerber_is_wp_ajax(),
			'interim'        => isset( $_REQUEST['interim-login'] ) ? 1 : 0,
			'total_attempts' => 0, // Never reset by PIN regeneration
		);

		if ( ! self::update_2fa_data( $data, $user->ID ) ) {
			return new WP_Error( '2fa-error', 'Unable to save 2FA challenge data for the user #' . $user->ID );
		}

		if ( ! $pin = self::generate_pin( $user->ID ) ) {
			return new WP_Error( '2fa-error', 'Unable to create PIN for the user #' . $user->ID );
		}

		return $pin;

	}

	/**
	 * Generates PIN and its expiration
	 *
	 * @param $user_id
	 *
	 * @return bool|string
	 */
	private static function generate_pin( $user_id ) {

		$pin = substr( str_shuffle( '1234567890' ), 0, CERBER_PIN_LENGTH );

		$data = array(
			'pin'      => $pin,
			'expires'  => time() + CERBER_PIN_EXPIRES * 60,
			'attempts' => 0,
			'ip'       => cerber_get_remote_ip(),
			'ua'       => sha1( $_SERVER['HTTP_USER_AGENT'] ?? '' ),
			'ua_raw'   => substr( trim( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 200 ),
			'2email'   => self::get_user_email( $user_id )
		);

		if ( self::update_2fa_data( $data, $user_id ) ) {

			self::send_user_pin( $user_id, $pin );

			return $pin;
		}

		return false;

	}

	/**
     * Pre-checks: make sure WordPress has properly identified the user.
     *
	 * If a PIN is submitted and the user is not identified, sends an error response and terminates
	 * the request. A pending session cookie rejection is handled first, because the request ends
	 * before 'init', where it is normally handled.
	 *
	 * @param $user_id
	 *
	 * @return void
	 */
	static function check_for_errors( $user_id ) {
		if ( ! cerber_get_post( 'the_2fa_nonce' )
		     || ! cerber_get_post( 'cerber_verify_pin' ) ) {
			return;
		}

		if ( ! $user_id ) {
			crb_process_session_cookie_rejection();
			self::send_ajax_response( 'Authentication error: WordPress user is not identified.' );
		}
	}

	/**
	 * @param int $current_user_id Current user ID
     *
	 */
	static function restrict_and_verify( $current_user_id = null ) {
		static $done = false;

		if ( $done ) {
			return;
		}

    	$done = true;

		if ( ! $current_user_id
             && ! $current_user_id = get_current_user_id() ) {
			return;
		}

		$twofactor = self::get_2fa_data( $current_user_id );

		if ( empty( $twofactor['pin'] ) ) {
			return;
        }

		// An active account lock prevents completing a pending challenge. It is checked before
		// the exemptions below because each of them would complete the pending session without a PIN.

		if ( crb_is_auth_locked( $current_user_id ) ) {
			self::end_pending_challenge( 543, add_query_arg( 'cerber_auth_abort', 'locked', wp_login_url() ), crb_get_auth_lock_notice() );
		}

		if ( crb_acl_is_allowed() ) {
			self::delete_2fa( $current_user_id );

			return;
		}

		// Check user settings again: they can be changed by admin after the user was enforced to complete 2FA

        $user_mode = self::get_user_meta_data( 'tfm', $current_user_id);

		if ( $user_mode === 2 ) {
			self::delete_2fa( $current_user_id, true );

			return;
		}
        elseif ( ! $user_mode ) {
			$user = wp_get_current_user();
	        if ( ! self::check_role_policies( $current_user_id, $user->roles ) ) {
				self::delete_2fa( $current_user_id );

				return;
			}
		}

		// Check the browser and user context

		if ( ( $sts = ( $twofactor['ip'] != cerber_get_remote_ip() ? 540 : 0 ) )
		     || ( $sts = ( $twofactor['ua'] != sha1( crb_array_get( $_SERVER, 'HTTP_USER_AGENT', '' ) ) ? 541 : 0 ) )
		     || ( $sts = ( cerber_is_ip_allowed() ? 0 : CRB_Globals::$act_status ) ) ) {

			self::delete_2fa( $current_user_id );
			crb_force_current_user_logout( $sts );
			crb_redirect( get_home_url() );

			exit;
		}

		// User wants to abort 2FA?

		if ( $now = cerber_get_get( 'cerber_2fa_now' ) ) {
			$go = null;
			if ( $now == 'different' ) {
				$go = wp_login_url( ( ! empty( $twofactor['to'] ) ) ? urldecode( $twofactor['to'] ) : '' );
			}
			if ( $now == 'cancel' ) {
				$go = get_home_url();
			}
			if ( $go ) {
				crb_force_current_user_logout( 28 );

				crb_redirect( $go );
				exit;
			}
		}

		// The lifetime PIN failure budget is checked before a possible PIN regeneration, which never restores it

		if ( self::get_failed_pin_count( $twofactor ) >= self::PIN_FAILURE_BUDGET ) {
			self::end_exhausted_challenge();
		}

		$pin_expired = false;

        if ( $twofactor['expires'] < time() ) {
			self::generate_pin( $current_user_id );
			$pin_expired = true;
		}

		// The first step of verification, ajax
		if ( cerber_is_http_post() ) {
			self::process_ajax( $pin_expired );
		}

		// The second, final step of verification
		if ( cerber_is_http_post()
		     && ! empty( $twofactor['nonce'] )
		     && $_POST['cerber_tag'] === $twofactor['nonce']
		     && ( $pin = cerber_get_post( 'cerber_pin' ) )
		     && self::verify_pin( trim( $pin ) ) ) {

			self::delete_2fa( $current_user_id );

			cerber_log( CRB_EV_LIN, $twofactor['login'], $current_user_id, 27 );
			crb_update_login_history( $current_user_id, true );

			cerber_2fa_checker( true );

			self::save_remember_device( $current_user_id );

			crb_sessions_update( $current_user_id, self::get_session_token_hash(), array( 'mfa_status' => 2 ) );

			$url = ( ! empty( $twofactor['to'] ) ) ? $twofactor['to'] : get_home_url();

			crb_safe_redirect( $url );
			exit;
		}

		self::show_2fa_page();
		exit;
	}

	/**
	 * Returns the number of days for which we will remember the user's device.
	 * Picks the smallest number if the user has multiple roles.
	 *
	 * @param int $user_id
	 *
	 * @return int
	 *
	 * @since 9.5.7
	 */
	private static function get_user_days( $user_id = null ) {
		if ( ! $user_id ) {
			$user = wp_get_current_user();
		}
		else {
			$user = get_userdata( $user_id );
		}

		// User policies

		if ( lab_lab() ) {

	        $cus = cerber_get_set( CRB_USER_SET, $user->ID );

			if ( is_numeric( $cus['tfremember'] ?? false ) ) {
				return $cus['tfremember'];
			}
        }

        // Roles policies

		if ( ! $user->roles ) {
			return 0;
		}

		$list = array();

		foreach ( $user->roles as $role ) {
			$policies = cerber_get_role_policies( $role );
			$list[] = (int) $policies['2faremember'] ?? 0;
		}

		return min( $list );
	}

	/**
	 * @param int $user_id
	 *
	 * @return void
     *
     * @since 9.5.7
	 */
	private static function save_remember_device( $user_id ) {
		if ( cerber_get_post( 'cerber_trust_device' ) != 'yes'
		     || ! $days = self::get_user_days( $user_id ) ) {
			return;
		}

		$salt = crb_random_string( 8, 12 );

        // Unique name for all users and websites on the domain

		$name = 'crb_tf_' . sha1( $salt . cerber_get_site_url() . '|' . $user_id );

		$val = '(' . rand( 0, 99 ) . ')'; // Can be any value
		$until = time() + DAY_IN_SECONDS * $days; // expires
        $expires = $until + DAY_IN_SECONDS * rand( 0, 3 ); // add some randomness to make it harder to find expiration time

		if ( cerber_set_cookie( $name, $val, $expires, '', '', true ) ) {

			$cus = cerber_get_set( CRB_USER_SET, $user_id );
			$cook_list = ( isset( $cus['tf_remember'] ) && is_array( $cus['tf_remember'] ) ) ? $cus['tf_remember'] : array();
			$cook_list[ $name ] = array( $val, $until );
			$cus['tf_remember'] = $cook_list;

			cerber_update_set( CRB_USER_SET, $cus, $user_id );
		}

		self::remove_expired_cookies( $user_id );
	}

	/**
     * Removes stored but expired device cookies
     *
	 * @param int $user_id
	 *
	 * @return void
     *
     * @since 9.5.7
	 */
	static function remove_expired_cookies( $user_id ) {

		$cus = cerber_get_set( CRB_USER_SET, $user_id );
		$cook_list = ( isset( $cus['tf_remember'] ) && is_array( $cus['tf_remember'] ) ) ? $cus['tf_remember'] : array();

        if ( ! $cook_list ) {
			return;
		}

        $update = false;

        foreach ( $cook_list as $coo_name => $coo_data ) {
			if ( $coo_data[1] < time() ) {
				unset( $cook_list[ $coo_name ] );
				$update = true;
			}
		}

        if ( $update ) {
			$cus['tf_remember'] = $cook_list;
			cerber_update_set( CRB_USER_SET, $cus, $user_id );
		}
	}

	static function process_ajax( $pin_expired = false ) {
		if ( ( ! $nonce = cerber_get_post( 'the_2fa_nonce', '\w+' ) )
		     || ( ! $pin = cerber_get_post( 'cerber_verify_pin' ) ) ) {
			return;
		}

		$err = '';

		if ( ! wp_verify_nonce( $nonce, 'crb-ajax-2fa' ) ) {
			$err = 'Nonce error.';
		}
        elseif ( $pin_expired ) {
			$err = __( 'This verification PIN code is expired. We have just sent a new one to your email.', 'wp-cerber' );
		}
        elseif ( ! self::verify_pin( trim( $pin ), $nonce ) ) {
			$err = __( 'You have entered an incorrect verification PIN code', 'wp-cerber' );
		}

		self::send_ajax_response( $err );
	}

	/**
	 * @param string $err
	 *
	 * @return void
	 */
	private static function send_ajax_response( $err ) {
		echo json_encode( array( 'error' => $err ) );
		exit;
	}

	/**
	 * Verifies the PIN entered for the pending 2FA challenge of the current session.
	 *
	 * An incorrect PIN increments both the per-PIN counter (attempts) and the lifetime counter
	 * of the challenge (total_attempts). The incorrect PIN that exhausts the lifetime budget ends
	 * the pending challenge and terminates the request. If the incremented counters cannot be
	 * saved, the pending challenge is ended and the request is terminated as well, so an uncounted
	 * attempt is not possible.
	 *
	 * @param string $pin The PIN entered by the user.
	 * @param string|null $nonce If provided and the PIN is correct, the nonce is saved to authorize the final verification step.
	 *
	 * @return bool True if the PIN is correct, false otherwise.
	 */
	private static function verify_pin( $pin, $nonce = null ) {

		$data = self::get_2fa_data();

		if ( empty( $data['pin'] )
		     || $data['expires'] < time() ) {
			return false;
		}

		if ( (string) $pin === (string) $data['pin'] ) {
			$ret = true;
			if ( ! $nonce ) {
				return $ret;
			}
			$data['nonce'] = $nonce;

			self::update_2fa_data( $data );

			return $ret;
		}

		// Count the incorrect PIN; the lifetime counter must be computed before the per-PIN counter changes

		$data['total_attempts'] = self::get_failed_pin_count( $data ) + 1;
		$data['attempts'] ++;

		if ( ! self::update_2fa_data( $data ) ) {
			cerber_error_log( 'Unable to save the failed 2FA PIN attempt of the user #' . get_current_user_id(), '2FA' );
			self::end_pending_challenge( 542, get_home_url(), __( 'Verification failed. Please sign in again.', 'wp-cerber' ) );
		}

		// The incorrect PIN that exhausts the budget ends the challenge at once, not on the next request

		if ( $data['total_attempts'] >= self::PIN_FAILURE_BUDGET ) {
			self::end_exhausted_challenge();
		}

		return false;
	}

	/**
	 * Ends the pending 2FA challenge of the current session whose lifetime PIN failure budget is exhausted.
	 *
	 * Applies the soft IP lockout used for excessive 2FA attempts (reason 721), then ends the
	 * pending session with status 542 and terminates the request.
	 *
	 * @return void This method terminates the request.
	 *
	 * @since 9.9.6
	 */
	private static function end_exhausted_challenge(): void {
		crb_apply_soft_ip_lockout( cerber_get_remote_ip(), 721 );
		self::end_pending_challenge( 542, get_home_url(), __( 'You have exceeded the number of allowed attempts to enter a verification PIN code. Please sign in again.', 'wp-cerber' ) );
	}

	/**
	 * Returns the number of incorrect PINs entered over the lifetime of a pending 2FA challenge.
	 *
	 * Records created before the lifetime counter was introduced have no total_attempts field.
	 * For them, the per-PIN counter is used as the best available value.
	 *
	 * @param array<string,mixed> $twofactor The 2FA challenge record of a session.
	 *
	 * @return int The number of incorrect PINs.
	 *
	 * @since 9.9.6
	 */
	private static function get_failed_pin_count( array $twofactor ): int {
		return (int) ( $twofactor['total_attempts'] ?? $twofactor['attempts'] ?? 0 );
	}

	/**
	 * Ends the pending 2FA challenge of the current session and terminates the request.
	 *
	 * Logs out the current session, which is the pending (not yet verified) session in this
	 * context, and deletes its 2FA data. Responds to an AJAX PIN verification request with
	 * the given message, otherwise redirects to the given URL. If the redirect is canceled,
	 * the request is terminated with an error response.
	 *
	 * @param int $status Activity status for the logout.
	 * @param string $redirect_url Local URL to redirect to.
	 * @param string $ajax_error Message for the user in response to an AJAX PIN verification request.
	 *
	 * @return void This method terminates the request.
	 *
	 * @since 9.9.6
	 */
	private static function end_pending_challenge( int $status, string $redirect_url, string $ajax_error ): void {

		crb_force_current_user_logout( $status );

		if ( cerber_get_post( 'the_2fa_nonce' ) ) {
			self::send_ajax_response( $ajax_error );
		}

		if ( crb_safe_redirect( $redirect_url ) ) {
			exit;
		}

		wp_die( 'Unable to complete the verification. Please sign in again.', 'Authentication error', array( 'response' => 403 ) );
	}

	static function show_2fa_page( $echo = true ) {
		@ini_set( 'display_errors', 0 );

		if ( ! defined( 'CONCATENATE_SCRIPTS' ) ) {
			define( 'CONCATENATE_SCRIPTS', false );
			define( 'CONCATENATE_SCRIPTS_BY_CRB', true );
		}

        // Workaround to avoid warning messages generated _wp_scripts_maybe_doing_it_wrong()
        global $wp_actions;
		$wp_actions['wp_enqueue_scripts'] = 1;
        // --------------------------------------------------------------------

		wp_enqueue_script( 'jquery' );

		ob_start();
		?>
        <!DOCTYPE html>
        <html style="height: 100%;">
        <head>
            <meta charset="UTF-8">
            <title><?php _e( 'Please verify that it’s you', 'wp-cerber' ); ?></title>
            <style>
                body {
                    height: 90%;
                    text-align: center;
                    font-family: Arial, Helvetica, sans-serif;
                    color: #555;
                }
                #cerber_2fa_page {
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    text-align: center;
                    height: 90%;
                }
                #cerber_2fa_wrap {
                    text-align: center;
                    background-color: #eee;
                    border-top: solid 4px #ddd;
                    padding: 1.5em 3em 1.5em 3em;
                }
                #cerber_2fa_inner  {
                    width: 350px;
                }
                @media (-webkit-min-device-pixel-ratio: 2) and (max-width: 1000px),
                (min-resolution: 192dpi) and (max-width: 1000px), {
                    #cerber_2fa_inner {
                        width: 100%;
                    }
                }
                @media screen and (max-width: 900px) {
                    #cerber_2fa_inner {
                        /*width: 100%;*/
                    }
                }
                #cerber_2fa_msg {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    /*height: 80px;*/
                    padding: 40px 0 40px 0;
                    background-color: #FF4633;
                    color: #fff;
                    opacity: 0.9;
                }
                #cerber_2fa_title {
                    color:#000;
                }
                #cerber_2fa_info{
                    color: #333;
                }
                #cerber_2fa_form {
                    margin-bottom: 3em;
                }
                #cerber_2fa_form input[type="text"] {
                    color: #000;
                    text-align: center;
                    font-size: 1.4em;
                    letter-spacing: 0.1em;
                    padding: 5px;
                    min-width: 140px;
                    border-radius: 4px;
                }
                #cerber_2fa_form input[type="submit"] {
                    color: white;
                    background: #0085ba;
                    /*background: #0073aa;*/
                    border: 0;
                    font-size: 1em;
                    font-weight: 600;
                    letter-spacing: 0.05em;
                    text-align: center;
                    cursor: pointer;
                    padding: 1em;
                    min-width: 150px;
                    border-radius: 4px;
                }
                #cerber_2fa_trust_device {
                    margin: 1.3em 0;
                }
                #cerber_2fa_trust_device > * {
                    vertical-align: middle;
                    cursor: pointer;
                }
                #cerber_2fa_trust_device > input {
                    width: 1.1em;
                    height: 1.1em;
                    margin-right: 0.5em;
                }
            </style>
			<?php

            // -------------------------------------------
            // Because print_head_scripts() -> 'wp_print_scripts' hook -> wp_just_in_time_script_localization() -> AUTOSAVE_INTERVAL

            if ( ! defined( 'AUTOSAVE_INTERVAL' ) ) {
				define( 'AUTOSAVE_INTERVAL', MINUTE_IN_SECONDS );
			}

            print_head_scripts();
			// -------------------------------------------

            ?>
            <script>

                var ajaxurl = "<?php echo admin_url( 'admin-ajax.php' ); ?>";
                var nonce2fa = "<?php echo wp_create_nonce( 'crb-ajax-2fa' ); ?>";

            </script>
        </head>

        <body>
        <div id="cerber_2fa_page">
			<?php
			self::cerber_2fa_form();
			?>
        </div>
        </body>
        </html>

		<?php

		$html = ob_get_clean();
		if ( $echo ) {
			echo $html;
		}

		return $html;
	}

	static function send_user_pin( $user_id, $pin ) {
		if ( ! $pin ) {
			return false;
		}

		$subj = __( 'Please verify that it’s you', 'wp-cerber' );
		$body = array();

		//$body[] = 'We need to verify that it’s you because you are trying to sign-in from a different device or a different location or you have not signed in for a long time. If this wasn’t you, please reset your password immediately.';
		$body[] = __( "You or someone else trying to log into the website. We have to verify that it's you. If this wasn't you, please immediately reset your password to safeguard your account.", 'wp-cerber' );
		/* translators: %s is the number of minutes the PIN code is valid. */
		$body[] = sprintf( __( 'Please use the following verification PIN code to verify your identity. The code is valid for %s minutes.', 'wp-cerber' ), CERBER_PIN_EXPIRES );
		$body[] = '';
		$body[] = $pin;

		$user_data = get_userdata( $user_id );

		$info_level = cerber_get_user_policy( '2faemailinfo', $user_data );

		if ( $info_level ) {
			$ds = array();
			/* translators: %s is the user login name. */
			$ds[] = sprintf( __( 'Login: %s', 'wp-cerber' ), $user_data->user_login );

			if ( $info_level == 2 ) {
				/* translators: %s is the IP address. */
				$ds[] = sprintf( __( 'IP address: %s', 'wp-cerber' ), cerber_get_remote_ip() );
				/* translators: %s is the hostname. */
				$ds[] = sprintf( __( 'Hostname: %s', 'wp-cerber' ), @gethostbyaddr( cerber_get_remote_ip() ) );

				if ( $c = lab_get_country( cerber_get_remote_ip(), false ) ) {
					/* translators: %s is the location (country name and code). */
					$ds[] = sprintf( __( 'Location: %s', 'wp-cerber' ), crb_get_country_name( $c ) . ' (' . $c . ')' );
				}
			}

			/* translators: %s is the browser user agent string. */
			$ds[] = sprintf( __( 'Browser: %s', 'wp-cerber' ), substr( strip_tags( crb_array_get( $_SERVER, 'HTTP_USER_AGENT', 'Not set' ) ), 0, 1000 ) );
			/* translators: %s is the date. */
			$ds[] = sprintf( __( 'Date: %s', 'wp-cerber' ), cerber_date( time(), false ) );

			$body[] = '';
			$body[] = __( 'Here are the details of the sign-in attempt', 'wp-cerber' );
			$body[] = implode( "\n", $ds );
		}

		$body = implode( "\n\n", $body );

		$email = self::get_user_email( $user_id );

		$user_name = trim( $user_data->user_firstname . ' ' . $user_data->user_lastname );
		$user_name = crb_sanitize_mail_display_name( $user_name );
		$to = $user_name ? '"' . $user_name . '" <' . $email . '>' : $email;

		$result = CRB_Messaging::send( '2fa', array(
			'subj' => $subj,
			'text' => $body
		), array( 'email' => 1, 'pushbullet' => 0 ), true, array( 'email_recipients' => array( $to ) ) );

		if ( $result && ( $user_data->user_email != $email ) ) {
		    // TODO Should we send a notification to the main user email?
		}

		return true;
	}

	static function get_user_email( $user_id = null ) {
		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		if ( lab_lab() ) {
			$cus = cerber_get_set( CRB_USER_SET, $user_id );
			if ( $cus
			     && ( $email = crb_array_get( $cus, 'tfemail' ) )
			     && is_email( $email ) ) {
				return $email;
			}
		}

		$data = get_userdata( $user_id );

		return $data->user_email;
	}

	/**
     * Return all valid user PINs
     *
	 * @param $user_id
	 *
	 * @return string
	 */
	static function get_user_pin_info( $user_id ) {

		if ( ! $cus = cerber_get_set( CRB_USER_SET, $user_id ) ) {
			return '';
		}

		if ( ! $fa = crb_array_get( $cus, '2fa' ) ) {
			return '';
		}

		$pins = '';

		foreach ( $fa as $entry ) {
			if ( empty( $entry['pin'] )
			     || $entry['expires'] < time() ) {
				continue;
			}

			if ( $ua = $entry['ua_raw'] ?? '' ) {
                $ua_info = crb_escape_html( CRB_User_Agent_Parser::detect( $ua ) ) . ' (' . crb_escape_html( $ua ) . ')';
			}
            else {
	            $ua_info = '';
            }

			$pins .= '<tr><td><code style="font-size: 110%;">' . $entry['pin'] . '</code></td><td>' . cerber_ago_time( $entry['expires'] ) . '</td><td>' . ( $entry['2email'] ?? '' ) . '</td><td>' . $ua_info . '</td></tr>';
		}

		if ( ! $pins ) {
			return '';
		}

		return '<div id="crb-admin-2fa-pins"><table><tr><td>PIN</td><td>Expires</td><td>Sent To</td><td>User Browser</td></tr>' . $pins . '</table></div>';

	}

	static function update_2fa_data( $data, $user_id = null ) {

		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		$cus = cerber_get_set( CRB_USER_SET, $user_id );

		if ( ! is_array( $cus ) ) {
			$cus = array();
		}

		if ( ! isset( $cus['2fa'] ) ) {
			$cus['2fa'] = array();
		}

		$old = self::cerber_2fa_session_id();
		$token = self::get_session_token_hash();

        // Move existing data from the deprecated format

		if ( $existing = $cus['2fa'][ $old ] ?? false ) {
			unset( $cus['2fa'][ $old ] );
			$cus['2fa'][ $token ] = $existing;
		}

		$cus['2fa'][ $token ] = array_merge( $cus['2fa'][ $token ] ?? [], $data );

		return cerber_update_set( CRB_USER_SET, $cus, $user_id );
	}

	/**
	 * Checks whether the session with the given token has a pending (not completed) 2FA challenge.
	 *
	 * Unlike get_2fa_data(), works for any session of the user, not only the current one.
	 * Recognizes both the current (hashed token) and the deprecated (raw token) record keys.
	 *
	 * @param int $user_id WordPress user ID.
	 * @param string $token WordPress session token (not hashed).
	 *
	 * @return bool True if the session has a pending 2FA challenge, false otherwise.
	 *
	 * @since 9.9.6
	 */
	static function is_challenge_pending( int $user_id, string $token ): bool {

		$cus = cerber_get_set( CRB_USER_SET, $user_id );

		if ( ! is_array( $cus ) || empty( $cus['2fa'] ) ) {
			return false;
		}

		$challenge = $cus['2fa'][ cerber_hash_token( $token ) ] ?? $cus['2fa'][ $token ] ?? array();

		return ! empty( $challenge['pin'] );
	}

	/**
     * Returns 2FA data for the current user session
     *
	 * @param int $current_user_id
	 *
	 * @return array
	 */
	static function get_2fa_data( $current_user_id = null ) {

        if ( ! $current_user_id ) {
			$current_user_id = get_current_user_id();
		}

		if ( ! $cus = cerber_get_set( CRB_USER_SET, $current_user_id ) ) {
			return array();
		}

		if ( empty( $cus['2fa'] ) ) {
			return array();
		}

		if ( $ret = $cus['2fa'][ self::get_session_token_hash() ] ?? false ) {
            return $ret;
		}

        // Deprecated format

		if ( $ret = $cus['2fa'][ self::cerber_2fa_session_id() ] ?? false ) {
			return $ret;
		}

		return array();
	}

	/**
     * Deletes all 2FA data for any given user, or the current session 2FA data of the current user
     *
	 * @param int $uid If $all is false, may be only the current user ID
	 * @param bool $all If false, deletes current session 2FA data for the current user
	 *
	 * @return void
	 */
	static function delete_2fa( $uid, $all = false ) {

		if ( ! $uid = absint( $uid ) ) {
			return;
		}

        $cus = cerber_get_set( CRB_USER_SET, $uid );

        if ( $cus && isset( $cus['2fa'] ) ) {
			if ( $all ) {
				unset( $cus['2fa'] );
			}
			else {
				unset( $cus['2fa'][ self::get_session_token_hash() ] );
				unset( $cus['2fa'][ self::cerber_2fa_session_id() ] );
			}

			cerber_update_set( CRB_USER_SET, $cus, $uid );
		}
	}

	/**
     * Return WordPress session token for the current user session
     *
	 * @return string
     *
     * @deprecated since 9.6.3.2
	 */
	static function cerber_2fa_session_id() {
		if ( self::$token ) {
			return self::$token;
		}

		return crb_get_session_token();
	}

	/**
     * Returns hashed WordPress session token for the current user session
     * The hash can be stored in the DB safely
     *
	 * @return string
     *
     * @since 9.6.3.2
	 */
	static function get_session_token_hash() {
		$token = ( self::$token ) ?: crb_get_session_token();

		return cerber_hash_token( $token );
	}

	static function cerber_2fa_form() {

		$max    = CERBER_PIN_LENGTH;
		$atts   = 'pattern="\d{' . $max . '}" maxlength="' . $max . '" size="' . $max . '" title="' . __( 'only digits are allowed', 'wp-cerber' ) . '"';
		$email = self::get_user_email();
		/* translators: %s is the masked email address. */
		$text = sprintf( __( "We've sent a verification PIN code to your email %s", 'wp-cerber' ), cerber_mask_email( $email ) ) .
		        '<p>'. __( 'Enter the code from the email in the field below.', 'wp-cerber' ).'</p>';
		//$change = '<a href="' . cerber_get_home_url() . '/?cerber_2fa_now=different">' . __( 'Sign in with a different account', 'wp-cerber' ) . '</a>';
		$change = '<a href="' . cerber_get_home_url() . '/?cerber_2fa_now=different">' . __( 'Try again', 'wp-cerber' ) . '</a>';
		$cancel = '<a href="' . cerber_get_home_url() . '/?cerber_2fa_now=cancel">' . __( 'Cancel', 'wp-cerber' ) . '</a>';
		$links = '<p>' . __( 'Did not receive the email?', 'wp-cerber' ) . '</p>' .
                 /* translators: 1: "Try again" link, 2: "Cancel" link */
                 sprintf( __( '%1$s or %2$s', 'wp-cerber' ), $change, $cancel );

		$trust = '';

		if ( $days = self::get_user_days() ) {
			/* translators: %d is the number of days the device will be remembered. */
			$trust = '<p id="cerber_2fa_trust_device"><input name="cerber_trust_device" id="trust_this_device" type="checkbox" value="yes"><label for="trust_this_device">' . sprintf( __( 'Remember this device for %d days', 'wp-cerber' ), $days ) . '</label></p>';
		}

		?>

        <div id="cerber_2fa_msg"></div>
        <div id="cerber_2fa_box">
            <div id="cerber_2fa_wrap">
                <div id="cerber_2fa_inner">
                    <h1 id="cerber_2fa_title"><?php _e( "Verify it's you", 'wp-cerber' ); ?></h1>
                    <div id="cerber_2fa_info"><?php echo $text; ?></div>
                    <form id="cerber_2fa_form" method="post" data-verified="no">
                        <p><input required type="text" name="cerber_pin" <?php echo $atts; ?> ></p>
                        <p><input type="hidden" name="cerber_tag" value="2FA"></p>

                        <?php echo $trust; ?>

                        <p><input type="submit" value="<?php _e( 'Verify', 'wp-cerber' ); ?>"></p>
                    </form>
                </div>
            </div>
			<?php echo $links; ?>
        </div>
        <script>
            jQuery( function( $ ) {
                let cform = $('#cerber_2fa_form');
                let umsg = 'cerber_2fa_msg';
                cform.submit(function (event) {
                    crb_hide_user_msg();
                    if (cform.data('verified') === 'yes') {
                        return;
                    }
                    event.preventDefault();
                    $.post(ajaxurl, {
                            the_2fa_nonce: nonce2fa,
                            cerber_verify_pin: $(this).find('input[type="text"]').val()
                        },
                        function (server_response, textStatus, jqXHR) {
                            let server_data = JSON.parse(server_response);
                            if (server_data.error.length === 0) {
                                cform.find('[name="cerber_tag"]').val(nonce2fa);
                                cform.data('verified', 'yes');
                                cform.submit();
                            }
                            else {
                                crb_display_user_msg(server_data['error']);
                            }
                        }
                    ).fail(function (jqXHR, textStatus, errorThrown) {
                        let err = errorThrown + ' ' + jqXHR.status;
                        alert(err);
                        console.error('Server Error: ' + err);
                    });
                });

                function crb_display_user_msg(msg) {
                    $('#' + umsg).fadeIn(500).html(msg);
                    setTimeout(function (args) {
                        crb_hide_user_msg();
                    }, 5000);
                }

                function crb_hide_user_msg() {
                    document.getElementById(umsg).style.display = "none";
                }
            });
        </script>
		<?php
	}
}

/**
 * @param $user WP_User
 *
 * @return string
 */
function cerber_2fa_get_redirect_to( $user ) {
	if ( isset( $_REQUEST['redirect_to'] ) ) {
		$redirect_to = $_REQUEST['redirect_to'];
		$requested_redirect_to = $redirect_to;
	}
	else {
		$redirect_to = admin_url();
		$requested_redirect_to = '';
	}

	$redirect_to = apply_filters( 'login_redirect', $redirect_to, $requested_redirect_to, $user );

	return $redirect_to;
}

/**
 * Verify that 2FA on the website works
 * If it works, 2FA can be enabled for admins
 *
 */
function cerber_2fa_checker( $save = false ) {
	if ( $save ) {
		cerber_update_set( 'cerber_2fa_is_ok', 1, null, false );
	}
	else {
		if ( cerber_get_set( 'cerber_2fa_is_ok', null, false ) ) {
			return true;
		}

		return false;
	}
}
