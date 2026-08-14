<?php

require_once(realpath(dirname(__FILE__)) . '/constructNotifications.php');
require_once(realpath(dirname(__FILE__)) . '/cveNotificationMail.php');

$mailBuilder = new CveNotificationMail();

foreach ($notifications as $email => $notification) {

    $subject = $mailBuilder->getSubject();
    $body = $mailBuilder->getBody($notification);

    if (!mail($email, $subject, $body)) {
        Utils::log(
            LOG_ERR,
            "Failed to send Pakiti notification to " . $email,
            __FILE__,
            __LINE__
        );
    }
}