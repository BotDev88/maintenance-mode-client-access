<?php
/**
 * Plugin Name: Client Access Manager
 * Description: Manages client access to the frontend while keeping full admin access unrestricted.
 * Version: 2.0.0
 * Author: Louis Botha
 * Author URI: https://bothamediagroup.co.za
 * License: GPL-2.0+
 * Text Domain: client-access-manager
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define plugin constants
define('CAM_VERSION', '1.0.0');
define('CAM_PATH', plugin_dir_path(__FILE__));
define('CAM_URL', plugin_dir_url(__FILE__));
define('CAM_BASENAME', plugin_basename(__FILE__));

/**
 * Class to handle the client access functionality
 */
class Client_Access_Manager {
    
    /**
     * Store plugin options to reduce database queries
     */
    private $options = [];
    
    /**
     * Initialize the plugin
     */
    public function __construct() {
        // Register activation hook
        register_activation_hook(__FILE__, array($this, 'activate'));
        
        // Register deactivation hook
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
        
        // Load options
        $this->load_options();
        
        // Add settings page
        add_action('admin_menu', array($this, 'add_settings_page'));
        
        // Register settings
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add media uploader scripts
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        
        // Check if client access management is enabled
        if ($this->options['enabled']) {
            // Add client access check
            add_action('template_redirect', array($this, 'client_access_check'));
            
            // Add admin bar notification
            add_action('admin_bar_menu', array($this, 'admin_bar_notice'), 100);
            
            // Add admin notice
            add_action('admin_notices', array($this, 'admin_notice'));
        }
        
        // Handle login redirection for client users
        add_filter('login_redirect', array($this, 'login_redirect'), 10, 3);
        
        // Add plugin action links
        add_filter('plugin_action_links_' . CAM_BASENAME, array($this, 'plugin_action_links'));
    }
    
    /**
     * Load all plugin options
     */
    private function load_options() {
        $this->options = [
            'enabled' => get_option('cam_enabled', false),
            'title' => get_option('cam_title', __('Down For Maintenance', 'client-access-manager')),
            'message' => get_option('cam_message', __('We are currently performing scheduled maintenance. Please check back soon.', 'client-access-manager')),
            'bg_color' => get_option('cam_bg_color', '#E60026'),
            'text_color' => get_option('cam_text_color', '#FFFFFF'),
            'logo_url' => get_option('cam_logo_url', ''),
            'ip_whitelist' => get_option('cam_ip_whitelist', ''),
            'secret_token' => get_option('cam_secret_token', ''),
        ];
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        // Create client role if it doesn't exist
        if (!get_role('client')) {
            add_role(
                'client',
                __('Client', 'client-access-manager'),
                array(
                    'read' => true,
                    'edit_posts' => false,
                    'delete_posts' => false,
                    'publish_posts' => false,
                    'upload_files' => false,
                )
            );
        }
        
        // Set default options
        if (false === get_option('cam_enabled')) {
            add_option('cam_enabled', false);
        }
        
        if (false === get_option('cam_title')) {
            add_option('cam_title', __('Down For Maintenance', 'client-access-manager'));
        }
        
        if (false === get_option('cam_message')) {
            add_option('cam_message', __('We are currently performing scheduled maintenance. Please check back soon.', 'client-access-manager'));
        }
        
        if (false === get_option('cam_bg_color')) {
            add_option('cam_bg_color', '#E60026'); // RGB 230, 0, 38
        }
        
        if (false === get_option('cam_text_color')) {
            add_option('cam_text_color', '#FFFFFF'); // White
        }
        
        if (false === get_option('cam_logo_url')) {
            add_option('cam_logo_url', '');
        }
        
        if (false === get_option('cam_ip_whitelist')) {
            add_option('cam_ip_whitelist', '');
        }
        
        // Use a hardcoded token instead of generating one
        if (false === get_option('cam_secret_token')) {
            // Hardcoded 55-character token
            $hardcoded_token = 'aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3cD5eF7gH9iJ1kL3';
            add_option('cam_secret_token', $hardcoded_token);
        }
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Disable client access management on deactivation
        update_option('cam_enabled', false);
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }
    
    
    /**
     * Enqueue admin scripts
     */
    public function enqueue_admin_scripts($hook) {
        if ('settings_page_cam-settings' !== $hook) {
            return;
        }
        
        wp_enqueue_media();
        
        // Register and enqueue admin script
        wp_register_script('cam-admin', CAM_URL . 'js/admin.js', array('jquery'), CAM_VERSION, true);
        
        // Localize script with AJAX URL and nonce
        wp_localize_script('cam-admin', 'camAjax', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('cam_generate_token_nonce'),
            'homeUrl' => home_url('/'),
            'pluginUrl' => CAM_URL,
            'debug' => WP_DEBUG,
            'version' => CAM_VERSION
        ));
        
        wp_enqueue_script('cam-admin');
        
        // Register and enqueue admin styles
        wp_register_style('cam-admin-style', CAM_URL . 'css/admin.css', array(), CAM_VERSION);
        wp_enqueue_style('cam-admin-style');
    }
    
    /**
     * Add settings page
     */
    public function add_settings_page() {
        add_options_page(
            __('Client Access Settings', 'client-access-manager'),
            __('Client Access', 'client-access-manager'),
            'manage_options',
            'cam-settings',
            array($this, 'settings_page')
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('cam_settings', 'cam_enabled', 'boolval');
        register_setting('cam_settings', 'cam_title', 'sanitize_text_field');
        register_setting('cam_settings', 'cam_message', 'wp_kses_post');
        register_setting('cam_settings', 'cam_bg_color', 'sanitize_hex_color');
        register_setting('cam_settings', 'cam_text_color', 'sanitize_hex_color');
        register_setting('cam_settings', 'cam_logo_url', 'esc_url_raw');
        register_setting('cam_settings', 'cam_ip_whitelist', array($this, 'sanitize_ip_whitelist'));
        // Removed cam_secret_token registration since it's now hardcoded
        
        add_settings_section(
            'cam_main_section',
            __('Client Access Settings', 'client-access-manager'),
            array($this, 'settings_section_callback'),
            'cam_settings'
        );
        
        add_settings_field(
            'cam_enabled',
            __('Enable Client Access Management', 'client-access-manager'),
            array($this, 'enabled_field_callback'),
            'cam_settings',
            'cam_main_section'
        );
        
        add_settings_field(
            'cam_title',
            __('Maintenance Page Title', 'client-access-manager'),
            array($this, 'title_field_callback'),
            'cam_settings',
            'cam_main_section'
        );
        
        add_settings_field(
            'cam_message',
            __('Maintenance Message', 'client-access-manager'),
            array($this, 'message_field_callback'),
            'cam_settings',
            'cam_main_section'
        );
        
        add_settings_field(
            'cam_colors',
            __('Colors', 'client-access-manager'),
            array($this, 'colors_field_callback'),
            'cam_settings',
            'cam_main_section'
        );
        
        add_settings_field(
            'cam_logo',
            __('Company Logo', 'client-access-manager'),
            array($this, 'logo_field_callback'),
            'cam_settings',
            'cam_main_section'
        );
        
        add_settings_section(
            'cam_security_section',
            __('Security Settings', 'client-access-manager'),
            array($this, 'security_section_callback'),
            'cam_settings'
        );
        
        add_settings_field(
            'cam_ip_whitelist',
            __('IP Whitelist', 'client-access-manager'),
            array($this, 'ip_whitelist_field_callback'),
            'cam_settings',
            'cam_security_section'
        );
        
        add_settings_field(
            'cam_secret_token',
            __('Secret Access Token', 'client-access-manager'),
            array($this, 'secret_token_field_callback'),
            'cam_settings',
            'cam_security_section'
        );
    }
    
    /**
     * Sanitize IP whitelist
     */
    public function sanitize_ip_whitelist($input) {
        $ips = explode(',', $input);
        $sanitized_ips = array();
        $invalid_ips = array();
        
        foreach ($ips as $ip) {
            $ip = trim($ip);
            if (empty($ip)) {
                continue;
            }
            
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $sanitized_ips[] = $ip;
            } else {
                $invalid_ips[] = $ip;
            }
        }
        
        // If there were invalid IPs, add an admin notice
        if (!empty($invalid_ips)) {
            add_settings_error(
                'cam_ip_whitelist',
                'invalid_ips',
                sprintf(
                    __('The following IPs were invalid and have been removed: %s', 'client-access-manager'),
                    implode(', ', $invalid_ips)
                ),
                'warning'
            );
        }
        
        return implode(',', $sanitized_ips);
    }
    
    /**
     * Settings section callback
     */
    public function settings_section_callback() {
        echo '<p>' . __('Configure the client access settings below.', 'client-access-manager') . '</p>';
    }
    
    /**
     * Security section callback
     */
    public function security_section_callback() {
        echo '<p>' . __('Configure additional security settings to control access to your site.', 'client-access-manager') . '</p>';
    }
    
    /**
     * Render field helper method
     */
    private function render_field($args) {
        $option = isset($this->options[$args['key']]) ? $this->options[$args['key']] : $args['default'];
        
        switch ($args['type']) {
            case 'checkbox':
                ?>
                <label>
                    <input type="checkbox" name="<?php echo esc_attr($args['name']); ?>" value="1" <?php checked($option, true); ?> />
                    <?php echo esc_html($args['label']); ?>
                </label>
                <?php
                break;
                
            case 'select':
                ?>
                <select name="<?php echo esc_attr($args['name']); ?>" id="<?php echo esc_attr($args['name']); ?>">
                    <?php foreach ($args['options'] as $value => $label) : ?>
                        <option value="<?php echo esc_attr($value); ?>" <?php selected($option, $value); ?>>
                            <?php echo esc_html($label); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                <?php
                break;
                
            case 'text':
                ?>
                <input type="text" name="<?php echo esc_attr($args['name']); ?>" id="<?php echo esc_attr($args['name']); ?>" value="<?php echo esc_attr($option); ?>" class="regular-text" />
                <?php
                break;
                
            case 'color':
                ?>
                <input type="color" name="<?php echo esc_attr($args['name']); ?>" id="<?php echo esc_attr($args['name']); ?>" value="<?php echo esc_attr($option); ?>" />
                <?php
                break;
        }
        
        if (!empty($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    /**
     * Enabled field callback
     */
    public function enabled_field_callback() {
        $this->render_field([
            'type' => 'checkbox',
            'name' => 'cam_enabled',
            'key' => 'enabled',
            'label' => __('Enable client access management', 'client-access-manager'),
            'default' => false,
            'description' => __('When enabled, the site will be in maintenance mode for public visitors. Admins have full access, and clients can view only the frontend.', 'client-access-manager'),
        ]);
    }
    
    /**
     * Title field callback
     */
    public function title_field_callback() {
        $this->render_field([
            'type' => 'select',
            'name' => 'cam_title',
            'key' => 'title',
            'default' => __('Down For Maintenance', 'client-access-manager'),
            'options' => [
                __('Down For Maintenance', 'client-access-manager') => __('Down For Maintenance', 'client-access-manager'),
                __('Under Construction', 'client-access-manager') => __('Under Construction', 'client-access-manager'),
            ],
        ]);
    }
    
    /**
     * Message field callback
     */
    public function message_field_callback() {
        $message = $this->options['message'];
        wp_editor($message, 'cam_message', array(
            'textarea_name' => 'cam_message',
            'textarea_rows' => 5,
            'media_buttons' => true,
            'teeny' => true,
        ));
    }
    
    /**
     * Colors field callback
     */
    public function colors_field_callback() {
        ?>
        <p>
            <label for="cam_bg_color"><?php _e('Background Color:', 'client-access-manager'); ?></label>
            <?php $this->render_field([
                'type' => 'color',
                'name' => 'cam_bg_color',
                'key' => 'bg_color',
                'default' => '#E60026',
            ]); ?>
        </p>
        <p>
            <label for="cam_text_color"><?php _e('Text Color:', 'client-access-manager'); ?></label>
            <?php $this->render_field([
                'type' => 'color',
                'name' => 'cam_text_color',
                'key' => 'text_color',
                'default' => '#FFFFFF',
            ]); ?>
        </p>
        <?php
    }
    
    /**
     * Logo field callback
     */
    public function logo_field_callback() {
        $logo_url = $this->options['logo_url'];
        ?>
        <div class="cam-logo-upload">
            <input type="hidden" name="cam_logo_url" id="cam_logo_url" value="<?php echo esc_attr($logo_url); ?>" />
            
            <div class="cam-logo-preview" style="margin-bottom: 10px;">
                <?php if (!empty($logo_url)) : ?>
                    <img src="<?php echo esc_url($logo_url); ?>" alt="<?php _e('Logo Preview', 'client-access-manager'); ?>" style="max-width: 50px; max-height: 50px; display: block; margin-bottom: 10px;" />
                <?php endif; ?>
            </div>
            
            <button type="button" class="button cam-upload-logo" id="cam_upload_logo_button">
                <?php _e('Select Logo', 'client-access-manager'); ?>
            </button>
            
            <?php if (!empty($logo_url)) : ?>
                <button type="button" class="button cam-remove-logo" id="cam_remove_logo_button">
                    <?php _e('Remove Logo', 'client-access-manager'); ?>
                </button>
            <?php endif; ?>
            
            <p class="description"><?php _e('Select a company logo to display in the top left corner of the maintenance page (recommended: 50x50px). Larger images will be scaled down.', 'client-access-manager'); ?></p>
        </div>
        <?php
    }
    
    /**
     * IP whitelist field callback
     */
    public function ip_whitelist_field_callback() {
        $ip_whitelist = $this->options['ip_whitelist'];
        ?>
        <textarea name="cam_ip_whitelist" id="cam_ip_whitelist" class="large-text code" rows="3"><?php echo esc_textarea($ip_whitelist); ?></textarea>
        <p class="description">
            <?php _e('Enter IP addresses that should bypass the maintenance mode, separated by commas. Both IPv4 and IPv6 are supported. Your current IP is:', 'client-access-manager'); ?>
            <code><?php echo esc_html($this->get_client_ip()); ?></code>
        </p>
        <?php
    }
    
    /**
     * Secret token field callback
     */
    public function secret_token_field_callback() {
        // Hardcoded 55-character token
        $hardcoded_token = 'aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3cD5eF7gH9iJ1kL3';
        
        // Update the option to ensure it's set
        update_option('cam_secret_token', $hardcoded_token);
        $this->options['secret_token'] = $hardcoded_token;
        
        ?>
        <input type="text" id="cam_secret_token" value="<?php echo esc_attr($hardcoded_token); ?>" class="regular-text code" readonly />
        <p class="description">
            <?php _e('This is your access token. It can be used to bypass the maintenance mode by adding it to the URL as a query parameter:', 'client-access-manager'); ?>
            <code class="cam-token-url-example"><?php echo esc_html(home_url('/?access_token=' . $hardcoded_token)); ?></code>
        </p>
        <p class="description">
            <strong><?php _e('Note:', 'client-access-manager'); ?></strong> 
            <?php _e('This token is hardcoded and cannot be changed.', 'client-access-manager'); ?>
        </p>
        <?php
    }
    
    /**
     * Settings page
     */
    public function settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('cam_settings');
                do_settings_sections('cam_settings');
                submit_button();
                ?>
            </form>
            
            <div class="card" style="max-width: 600px; margin-top: 20px; padding: 10px 20px;">
                <h2><?php _e('Client Access Instructions', 'client-access-manager'); ?></h2>
                <p><?php _e('To give clients access to view the frontend while in maintenance mode:', 'client-access-manager'); ?></p>
                <ol>
                    <li><?php _e('Create a new user with the "Client" role', 'client-access-manager'); ?></li>
                    <li><?php _e('Share the login credentials with your client', 'client-access-manager'); ?></li>
                    <li><?php _e('When they log in, they will be redirected to the frontend automatically', 'client-access-manager'); ?></li>
                </ol>
                <p><a href="<?php echo admin_url('user-new.php'); ?>" class="button"><?php _e('Add New User', 'client-access-manager'); ?></a></p>
            </div>
            
            <div class="card" style="max-width: 600px; margin-top: 20px; padding: 10px 20px;">
                <h2><?php _e('Bypass Methods', 'client-access-manager'); ?></h2>
                <p><?php _e('There are several ways to bypass the maintenance mode:', 'client-access-manager'); ?></p>
                <ol>
                    <li><?php _e('Log in as an admin or client user', 'client-access-manager'); ?></li>
                    <li><?php _e('Access from a whitelisted IP address', 'client-access-manager'); ?></li>
                    <li><?php _e('Use the secret access token in the URL', 'client-access-manager'); ?></li>
                </ol>
                <p><?php _e('These bypass methods provide flexibility while maintaining security.', 'client-access-manager'); ?></p>
            </div>
        </div>
        <?php
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        // Check for CloudFlare IP
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        }
        
        // Check for proxy IPs
        $ip_headers = array(
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_headers as $header) {
            if (isset($_SERVER[$header])) {
                $ip_list = explode(',', sanitize_text_field($_SERVER[$header]));
                return trim($ip_list[0]);
            }
        }
        
        // Default to REMOTE_ADDR if nothing else works
        return sanitize_text_field($_SERVER['REMOTE_ADDR']);
    }
    
    /**
     * Check if the current IP is whitelisted
     */
    private function is_ip_whitelisted() {
        if (empty($this->options['ip_whitelist'])) {
            return false;
        }
        
        $whitelisted_ips = array_map('trim', explode(',', $this->options['ip_whitelist']));
        $client_ip = $this->get_client_ip();
        
        return in_array($client_ip, $whitelisted_ips);
    }
    
    /**
     * Check if the secret token is valid
     */
    private function is_token_valid() {
        // Hardcoded 55-character token
        $hardcoded_token = 'aB7cD9eF1gH3iJ5kL7mN9oP1qR3sT5uV7wX9yZ1aB3cD5eF7gH9iJ1kL3';
        
        // Check if the token is in the URL
        if (isset($_GET['access_token']) && $_GET['access_token'] === $hardcoded_token) {
            // Set a cookie to remember the access with SameSite attribute
            $secure = is_ssl();
            $httponly = true;
            
            // For PHP 7.3+ use the SameSite attribute
            if (PHP_VERSION_ID >= 70300) {
                setcookie('cam_access', md5($hardcoded_token), [
                    'expires' => time() + 86400,
                    'path' => COOKIEPATH,
                    'domain' => COOKIE_DOMAIN,
                    'secure' => $secure,
                    'httponly' => $httponly,
                    'samesite' => 'Strict'
                ]);
            } else {
                // For older PHP versions
                setcookie('cam_access', md5($hardcoded_token), time() + 86400, COOKIEPATH, COOKIE_DOMAIN, $secure, $httponly);
            }
            
            return true;
        }
        
        // Check if the access cookie is set
        if (isset($_COOKIE['cam_access']) && $_COOKIE['cam_access'] === md5($hardcoded_token)) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Check if the site should be in maintenance mode for the current user
     */
    public function client_access_check() {
        // Skip for admin users - they always have full access
        if (current_user_can('manage_options')) {
            return;
        }
        
        // Skip for client users who are logged in - they can see the frontend
        if (is_user_logged_in() && $this->is_client_user()) {
            return;
        }
        
        // Skip for whitelisted IPs
        if ($this->is_ip_whitelisted()) {
            return;
        }
        
        // Skip if valid token is provided
        if ($this->is_token_valid()) {
            return;
        }
        
        // Skip for login page and admin
        global $pagenow;
        if ($pagenow === 'wp-login.php' || is_admin()) {
            return;
        }
        
        // If none of the bypass methods work, show maintenance page
        $this->display_maintenance_page();
        exit;
    }
    
    /**
     * Check if current user has client role
     */
    private function is_client_user() {
        $user = wp_get_current_user();
        return in_array('client', (array) $user->roles);
    }
    
    /**
     * Display the maintenance page
     */
    public function display_maintenance_page() {
        $title = $this->options['title'];
        $message = $this->options['message'];
        $bg_color = $this->options['bg_color'];
        $text_color = $this->options['text_color'];
        $logo_url = $this->options['logo_url'];
        
        // Send 503 status code
        status_header(503);
        nocache_headers();
        
        ?><!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title><?php echo esc_html($title); ?></title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                    margin: 0;
                    padding: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: <?php echo esc_attr($text_color); ?>;
                    background-color: <?php echo esc_attr($bg_color); ?>;
                    position: relative;
                }
                .maintenance-container {
                    max-width: 800px;
                    padding: 40px;
                    background-color: <?php echo esc_attr($bg_color); ?>;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
                    text-align: center;
                    margin: 20px;
                    position: relative;
                    color: <?php echo esc_attr($text_color); ?>;
                }
                h1 {
                    font-size: 32px;
                    margin-bottom: 20px;
                }
                .login-link {
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    width: 50px;
                    height: 50px;
                    border-radius: 50%;
                    background-color: #D2042D; /* Red background */
                    color: white;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    text-decoration: none;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
                    transition: all 0.3s ease;
                }
                .login-link:hover {
                    background-color: #B00020; /* Darker red on hover */
                    transform: scale(1.05);
                }
                .login-link svg {
                    width: 24px;
                    height: 24px;
                }
                .company-logo {
                    position: fixed;
                    top: 20px;
                    left: 20px;
                    width: 50px;
                    height: 50px;
                    z-index: 100;
                }
                .company-logo img {
                    width: 100%;
                    height: 100%;
                    object-fit: contain;
                }
            </style>
        </head>
        <body>
            <?php if (!empty($logo_url)) : ?>
            <div class="company-logo">
                <img src="<?php echo esc_url($logo_url); ?>" alt="<?php echo esc_attr(get_bloginfo('name')); ?> Logo" />
            </div>
            <?php endif; ?>
            
            <div class="maintenance-container">
                <h1><?php echo esc_html($title); ?></h1>
                <div><?php echo wp_kses_post($message); ?></div>
            </div>
            
            <a href="<?php echo esc_url(wp_login_url()); ?>" class="login-link" aria-label="<?php esc_attr_e('Log In', 'client-access-manager'); ?>">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                    <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
            </a>
        </body>
        </html>
        <?php
    }
    
    /**
     * Add admin bar notice
     */
    public function admin_bar_notice($wp_admin_bar) {
        if (current_user_can('manage_options')) {
            $wp_admin_bar->add_node(array(
                'id' => 'client-access-notice',
                'title' => __('Client Access Mode Active', 'client-access-manager'),
                'href' => admin_url('options-general.php?page=cam-settings'),
                'meta' => array(
                    'class' => 'cam-notice',
                    'title' => __('Client Access Mode is currently active', 'client-access-manager'),
                ),
            ));
            
            // Enqueue admin bar styles
            wp_enqueue_style('cam-admin-bar', CAM_URL . 'css/admin-bar.css', array(), CAM_VERSION);
            
            // Add inline style for the notice
            wp_add_inline_style('cam-admin-bar', '
                #wp-admin-bar-client-access-notice {
                    background-color: #d54e21 !important;
                    color: white !important;
                }
                #wp-admin-bar-client-access-notice .ab-item {
                    color: white !important;
                }
            ');
        
        }
    }
    
    /**
     * Add admin notice
     */
    public function admin_notice() {
        ?>
        <div class="notice notice-info">
            <p>
                <strong><?php _e('Client Access Mode is active.', 'client-access-manager'); ?></strong>
                <?php _e('Your website is only visible to admins and client users.', 'client-access-manager'); ?>
                <a href="<?php echo admin_url('options-general.php?page=cam-settings'); ?>"><?php _e('Manage Settings', 'client-access-manager'); ?></a>
            </p>
        </div>
        <?php
    }
    
    /**
     * Handle login redirection for client users
     */
    public function login_redirect($redirect_to, $requested_redirect_to, $user) {
        // Check if user exists and is a client
        if (isset($user->roles) && is_array($user->roles) && in_array('client', $user->roles)) {
            // Redirect client users to the home page
            return home_url();
        }
        
        // Return the default redirect for admins and other users
        return $redirect_to;
    }
    
    /**
     * Add plugin action links
     */
    public function plugin_action_links($links) {
        $settings_link = '<a href="' . admin_url('options-general.php?page=cam-settings') . '">' . __('Settings', 'client-access-manager') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }
}

// Initialize the plugin
$client_access_manager = new Client_Access_Manager();
