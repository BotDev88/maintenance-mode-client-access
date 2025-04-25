<?php
// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Delete options
delete_option('cam_enabled');
delete_option('cam_title');
delete_option('cam_message');
delete_option('cam_bg_color');
delete_option('cam_text_color');
delete_option('cam_logo_url');
delete_option('cam_ip_whitelist');
delete_option('cam_secret_token');

// Remove client role
if (get_role('client')) {
    remove_role('client');
}
