<?php
if ( !class_exists('InputValidator') )
	require(dirname(__FILE__).'/class-InputValidator.php');

class SpiritsAndGoblins_Admin {
	const OPTION_KEY  = 'spirits-and-goblins';
	const OPTION_PAGE = 'spirits-and-goblins';

	const USER_META_PHONE = 'phone_number';

	static $instance;

	private $options = array();
	private $plugin_basename;
	private $admin_hook, $admin_action;

	function __construct(){
		self::$instance = $this;

		$this->options = $this->get_option();
		$this->plugin_basename = plugin_basename(dirname(dirname(__FILE__)).'/plugin.php');

		add_action('admin_menu', array($this, 'admin_menu'));
		add_filter('plugin_action_links', array($this, 'plugin_setting_links'), 10, 2 );

		add_filter('user_contactmethods', array($this, 'user_contactmethods'), 10, 2);
	}

	static public function option_keys(){
		return array(
			'otp_length'   => __('One Time Password length', SpiritsAndGoblins::TEXT_DOMAIN),
			'otp_expires'  => __('One Time Password expires (sec)', SpiritsAndGoblins::TEXT_DOMAIN),
			'send_option'  => __('Send option', SpiritsAndGoblins::TEXT_DOMAIN),
			'twilio_sid'   => __('Twilio sid', SpiritsAndGoblins::TEXT_DOMAIN),
			'twilio_token' => __('Twilio token', SpiritsAndGoblins::TEXT_DOMAIN),
			'twilio_phone' => __('Twilio phone number', SpiritsAndGoblins::TEXT_DOMAIN),
			);
	}

	static public function get_option(){
		$options = get_option(self::OPTION_KEY);
		foreach (array_keys(self::option_keys()) as $key) {
			if (!isset($options[$key]) || is_wp_error($options[$key])) {
				switch($key){
				case 'otp_length';
					$options[$key] = SpiritsAndGoblins::OTP_LENGTH;
					break;
				case 'otp_expires';
					$options[$key] = SpiritsAndGoblins::OTP_EXPIRES;
					break;
				case 'send_option';
					$options[$key] = SpiritsAndGoblins::SEND_OPTION;
					break;
				default:
					$options[$key] = '';
				}
			}
		}
		return $options;
	}

	//**************************************************************************************
	// Add Admin Menu
	//**************************************************************************************
	public function admin_menu() {
		global $wp_version;

		$title = __('Spirits and Goblins', SpiritsAndGoblins::TEXT_DOMAIN);
		$this->admin_hook = add_options_page($title, $title, 'manage_options', self::OPTION_PAGE, array($this, 'options_page'));
		$this->admin_action = admin_url('/options-general.php') . '?page=' . self::OPTION_PAGE;
	}

	public function options_page(){
		$nonce_action  = 'update_options';
		$nonce_name    = '_wpnonce_update_options';

		$option_keys   = $this->option_keys();
		$this->options = $this->get_option();
		$title = __('Spirits and Goblins', SpiritsAndGoblins::TEXT_DOMAIN);

		$iv = new InputValidator('POST');
		$iv->set_rules($nonce_name, 'required');

		// Update options
		if (!is_wp_error($iv->input($nonce_name)) && check_admin_referer($nonce_action, $nonce_name)) {
			// Get posted options
			$fields = array_keys($option_keys);
			foreach ($fields as $field) {
				switch ($field) {
				case 'otp_length':
				case 'otp_expires':
					$iv->set_rules($field, array('trim','esc_html','numeric','required'));
					break;
				case 'send_option':
					$iv->set_rules($field, array('trim','esc_html','required'));
					break;
				default:
					$iv->set_rules($field, array('trim','esc_html'));
					break;
				}
			}
			$options = $iv->input($fields);
			$err_message = '';
			foreach ($option_keys as $key => $field) {
				if (is_wp_error($options[$key])) {
					$error_data = $options[$key];
					$err = '';
					foreach ($error_data->errors as $errors) {
						foreach ($errors as $error) {
							$err .= (!empty($err) ? '<br />' : '') . __('Error! : ', SpiritsAndGoblins::TEXT_DOMAIN);
							$err .= sprintf(
								__(str_replace($key, '%s', $error), SpiritsAndGoblins::TEXT_DOMAIN),
								$field
								);
						}
					}
					$err_message .= (!empty($err_message) ? '<br />' : '') . $err;
				}
				if (!isset($options[$key]) || is_wp_error($options[$key]))
					$options[$key] = '';
			}
			if (SpiritsAndGoblins::DEBUG_MODE && function_exists('dbgx_trace_var')) {
				dbgx_trace_var($options);
			}

			// Update options
			if ($this->options !== $options) {
				update_option(self::OPTION_KEY, $options);
				printf(
					'<div id="message" class="updated fade"><p><strong>%s</strong></p></div>'."\n",
					empty($err_message) ? __('Done!', SpiritsAndGoblins::TEXT_DOMAIN) : $err_message
					);
				$this->options = $options;
			}
			unset($options);
		}

?>
		<div class="wrap">
		<?php screen_icon(); ?>
		<h2><?php echo esc_html( $title ); ?></h2>
		<form method="post" action="<?php echo $this->admin_action;?>">
		<?php echo wp_nonce_field($nonce_action, $nonce_name, true, false) . "\n"; ?>
		<table class="wp-list-table fixed"><tbody>
		<?php foreach ($option_keys as $field => $label) { $this->input_field($field, $label); } ?>
		</tbody></table>
		<?php submit_button(); ?>
		</form>
		</div>
<?php
	}

	private function input_field($field, $label, $args = array()){
		extract($args);

		$label = sprintf('<th><label for="%1$s">%2$s</label></th>'."\n", $field, $label);

		switch ($field) {
		case 'send_option':
			$input_field  = sprintf('<td><select name="%1$s">', $field);
			$input_field .= '<option value=""></option>';
			$send_options = array(
				'mail' => __('EMail', SpiritsAndGoblins::TEXT_DOMAIN),
				'sms'  => __('Short Message', SpiritsAndGoblins::TEXT_DOMAIN),
				);
			foreach ($send_options as $key => $val) {
				$input_field .= sprintf(
					'<option value="%1$s"%2$s>%3$s</option>',
					esc_attr($key),
					$key == $this->options[$field] ? ' selected' : '',
					$val);
			}
			$input_field .= '</select></td>';
			break;
		default:
			$input_field = sprintf('<td><input type="text" name="%1$s" value="%2$s" id="%1$s" size=100 /></td>'."\n", $field, esc_attr($this->options[$field]));
		}

		echo "<tr>\n{$label}{$input_field}</tr>\n";
	}


	//**************************************************************************************
	// Add user contactmethods
	//**************************************************************************************
	public function user_contactmethods($user_contactmethods, $user){
		if ($this->options['send_option'] === 'sms')
			$user_contactmethods[self::USER_META_PHONE] = __('Phone number', SpiritsAndGoblins::TEXT_DOMAIN);
		return $user_contactmethods;
	}

	//**************************************************************************************
	// Add setting link
	//**************************************************************************************
	public function plugin_setting_links($links, $file) {
		if ($file === $this->plugin_basename) {
			$settings_link = '<a href="' . $this->admin_action . '">' . __('Settings') . '</a>';
			array_unshift($links, $settings_link); // before other links
		}

		return $links;
	}
}