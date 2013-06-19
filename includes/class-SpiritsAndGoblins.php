<?php
if ( !class_exists('Services_Twilio') )
	require dirname(__FILE__).'/twilio-php/Services/Twilio.php';
if ( !class_exists('otp') )
	require dirname(__FILE__).'/php-otp-1.1.1/class.otp.php';

class SpiritsAndGoblins {
	const TEXT_DOMAIN = 'spirits-and-goblins';

	const DEFAULT_SEQUENCE = 100;
	const OTP_ALGORITHM = 'sha1';
	const OTP_LENGTH = 6;

	static $instance;

	function __construct() {
		self::$instance = $this;

		add_action('login_form', array($this, 'login_form'));
		add_action('register_form', array($this, 'login_form'));
		add_action('login_form_otp', array($this, 'login_form_otp'));
		add_action('login_form_login', array($this, 'login_form_login'));
	}

	public function login_form_login(){
		global $action;

		$user_login = isset($_POST['log']) ? $_POST['log'] : '';
		$user_pwd   = isset($_POST['pwd']) ? $_POST['pwd'] : '';
		$user = wp_authenticate($user_login, $user_pwd);
		if (is_wp_error($user))
			return;

		if ( $action !== 'otp')
			wp_die(__('Unknown error!', self::TEXT_DOMAIN));
	}

	public function login_form(){
		echo '<input type="hidden" name="action" value="otp" />'."\n";
	}

	public function login_form_otp() {
		$secure_cookie = '';
		$interim_login = isset($_REQUEST['interim-login']);
		$customize_login = isset($_REQUEST['customize-login']);
		if ( $customize_login )
			wp_enqueue_script( 'customize-base' );

		$otpass = isset($_POST['otp']) ? intval($_POST['otp']) : false;
		$rememberme = isset($_POST['rememberme']) ? intval($_POST['rememberme']) : '';

		// get user
		if ( !$otpass ) {
			$user_login = isset($_POST['log']) ? $_POST['log'] : '';
			$user_pwd   = isset($_POST['pwd']) ? $_POST['pwd'] : '';
			$user = wp_authenticate($user_login, $user_pwd);
		} else {
			$user_login = '';
			if ( isset($_POST['log']) ) {
				$user_login = sanitize_user($_POST['log']);
				$user = get_user_by('login', $user_login);
			}
		}
		if ( !isset($user) || is_wp_error($user) )
			return;

		if ( !empty($user_login) && !force_ssl_admin() && $user && get_user_option('use_ssl', $user->ID) ) {
			$secure_cookie = true;
			force_ssl_admin(true);
		}

		if ( isset( $_REQUEST['redirect_to'] ) ) {
			$redirect_to = $_REQUEST['redirect_to'];
			// Redirect to https if user wants ssl
			if ( $secure_cookie && false !== strpos($redirect_to, 'wp-admin') )
				$redirect_to = preg_replace('|^http://|', 'https://', $redirect_to);
		} else {
			$redirect_to = admin_url();
		}
		$redirect_to = apply_filters('login_otp_redirect', $redirect_to);

		if ( !$secure_cookie && is_ssl() && force_ssl_login() && !force_ssl_admin() && ( 0 !== strpos($redirect_to, 'https') ) && ( 0 === strpos($redirect_to, 'http') ) )
			$secure_cookie = false;

		// verify One time Password
		$verify_otp = $this->verify_otp($user, $otpass);
		if ( !is_wp_error($verify_otp) ) {
			wp_set_auth_cookie($user->ID, $rememberme, $secure_cookie);
			do_action('wp_login', $user_login, $user);
			if ( $interim_login ) {
				$message = '<p class="message">' . __('You have logged in successfully.') . '</p>';
				login_header( '', $message );
?>

			<?php if ( ! $customize_login ) : ?>
			<script type="text/javascript">setTimeout( function(){window.close()}, 8000);</script>
			<p class="alignright">
			<input type="button" class="button-primary" value="<?php esc_attr_e('Close'); ?>" onclick="window.close()" /></p>
			<?php endif; ?>
			</div>
			<?php do_action( 'login_footer' ); ?>
			<?php if ( $customize_login ) : ?>
				<script type="text/javascript">setTimeout( function(){ new wp.customize.Messenger({ url: '<?php echo wp_customize_url(); ?>', channel: 'login' }).send('login') }, 1000 );</script>
			<?php endif; ?>
			</body></html>
<?php
					exit;
			}

			if ( ( empty( $redirect_to ) || $redirect_to == 'wp-admin/' || $redirect_to == admin_url() ) ) {
				// If the user doesn't belong to a blog, send them to user admin. If the user can't edit posts, send them to their profile.
				if ( is_multisite() && !get_active_blog_for_user($user->ID) && !is_super_admin( $user->ID ) )
					$redirect_to = user_admin_url();
				elseif ( is_multisite() && !$user->has_cap('read') )
					$redirect_to = get_dashboard_url( $user->ID );
				elseif ( !$user->has_cap('edit_posts') )
					$redirect_to = admin_url('profile.php');
			}
			wp_safe_redirect($redirect_to);
			exit();
		}

		// send One Time Password
		$this->send_otp($user);

		// One Time Password form
		login_header(__('Log In'), '', $otpass ? $verify_otp : null);
?>

<form name="loginform" id="loginform" action="<?php echo esc_url( site_url( 'wp-login.php', 'login_post' ) ); ?>" method="post">
	<p>
		<label for="user_otp"><?php _e('One time password', self::TEXT_DOMAIN) ?><br />
		<input type="text" name="otp" id="user_otp" class="input" value="<?php echo esc_attr($otpass); ?>" size="20" /></label>
	</p>
	<p class="submit">
		<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e('Log In'); ?>" />
<?php	if ( $interim_login ) { ?>
		<input type="hidden" name="interim-login" value="1" />
<?php	} else { ?>
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
<?php 	} ?>
<?php   if ( $customize_login ) : ?>
		<input type="hidden" name="customize-login" value="1" />
<?php   endif; ?>
		<input type="hidden" name="action" value="otp" />
		<input type="hidden" name="log" id="user_login" value="<?php echo esc_attr($user_login); ?>" />
		<input type="hidden" name="rememberme" id="rememberme" value="<?php echo esc_attr($rememberme); ?>" />
	</p>
</form>

<script type="text/javascript">
setTimeout( function(){ try{
d = document.getElementById('user_otp');
d.focus();
d.select();
} catch(e){}
}, 200);
if(typeof wpOnload=='function')wpOnload();
</script>

<?php
		login_footer();
		exit();
	}

	private function verify_otp($user, $otpass) {
		if ( !$user || !$user->exists() )
			return new WP_Error('not_logged_in', __('not logged in', self::TEXT_DOMAIN));

		$seq = get_user_meta($user->ID, 'sag_seq', true);
		if ( !$seq ) {
			$seq = self::DEFAULT_SEQUENCE;
			add_user_meta($user->ID, 'sag_seq', $seq, true);
		}
		$seq = intval($seq);

		$otpass = intval($otpass);
		$otpass_org = intval($this->get_otp($user, $seq));
		if ($otpass) {
			$seq--;
			if (!$seq) {
				$otp = new otp();
				update_user_meta($user->ID, 'sag_seed', $otp->generateSeed());
				update_user_meta($user->ID, 'sag_seq', self::DEFAULT_SEQUENCE);
			} else {
				update_user_meta($user->ID, 'sag_seq', $seq);
			}
		}

		return
			$otpass === $otpass_org
			? true
			: new WP_Error('otp_error', sprintf(__('One time password incorrect for %s', self::TEXT_DOMAIN), $user->get('display_name')));
	}

	private function get_otp($user = null, $seq = false) {
		if ( !isset($user) )
			$user = wp_get_current_user();
		if ( !$user || is_wp_error($user) )
			return false;

		$otp = new otp();

		$seed = get_user_meta($user->ID, 'sag_seed', true);
		if ( !$seed ) {
			$seed = $otp->generateSeed();
			update_user_meta($user->ID, 'sag_seed', $seed);
		}

		if ( !$seq ) {
			$seq = get_user_meta($user->ID, 'sag_seq', true);
			if ( !$seq ) {
				$seq = self::DEFAULT_SEQUENCE;
				add_user_meta($user->ID, 'sag_seq', $seq, true);
			}
		}
		$seq = intval($seq);

		if ( $pass = $otp->generateOtp($this->pass_phrase(), $seed, $seq, self::OTP_ALGORITHM) ) {
			$pass_dec = sprintf('%0'.self::OTP_LENGTH.'d', abs(hexdec($pass['hex_otp']) % pow(10,self::OTP_LENGTH)));
			//update_user_meta($user->ID, 'sag_otp', array('dec_otp' => $pass_dec, 'seequence_count' => $seq));
			return $pass_dec;
		} else {
			return false;
		}
	}

	private function pass_phrase() {
		return defined('AUTH_SALT') ? AUTH_SALT : (defined('COOKIEHASH') ? COOKIEHASH : md5(get_site_option('siteurl')));
	}

	private function send_otp($user) {
		if ( !isset($user) )
			$user = wp_get_current_user();
		if ( !$user || is_wp_error($user) )
			return false;

		if ( is_multisite() )
			$blogname = $GLOBALS['current_site']->site_name;
		else
			$blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
		$title = sprintf(__('[%s] Your one time password', self::TEXT_DOMAIN), $blogname);

		$message = $this->get_otp($user);

		wp_mail($user->user_email, $title, $message);
	}
}
