<?php

class CveNotificationMail {
    public function getSubject() {
        return 'Pakiti: tagged CVEs detected!';
    }

    public function getBody($notification) {
        
        $body = '';

        $body .= "Pakiti tagged CVE notification\n";
        $body .= "\n";

        foreach ($notification as $groupId => $group) {

            $body .= "HostGroup: " . $group['name'] . "\n";
            $body .= str_repeat('-', 60) . "\n";

            foreach ($group['hosts'] as $host) {

                $body .= "\n";
                $body .= "Host: " . $host['hostname'] . "\n";
                $body .= "Report ID: " . $host['reportId'] . "\n";
                $body .= "Received: " . $host['receivedOn'] . "\n";

                $body .= "Tagged CVEs:\n";

                foreach ($host['taggedCves'] as $cve) {
                    $body .= "  - " . $cve . "\n";
                }

                $body .= "\n";
            }

            $body .= "\n";
        }

        return $body;
    }

}