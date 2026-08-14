<?php

require(realpath(dirname(__FILE__)) . '/../../common/Loader.php');

/**
 * Use bootstrap initialization as per convention of this repo..
 * DB Managers should be used as repository interface connection.
 */

$hostsManager = $pakiti->getManager("HostsManager");
$reportsManager = $pakiti->getManager("ReportsManager");
$cvesManager = $pakiti->getManager("CvesManager");
$hostGroupsManager = $pakiti->getManager("HostGroupsManager");

/**
 * Ensure the host is relevant e.g. contains numOfCvesWithTag.
 */
$hosts = $hostsManager->getHosts(
    null, 
    -1, 
    -1, 
    null, 
    null, 
    true, 
    -1, 
    null
);

$notifications = array();

foreach ($hosts as $host) {

    /**
     * Ensure last report of host
     */
    $lastReportId = $host->getLastReportId();

    if ($lastReportId == -1) {
        continue;
    }

    $report = $reportsManager->getReportById($lastReportId);

    if ($report == null) {
        continue;
    }

    /**
     * Ensure the report is relevant e.g. contains actual Cve(s).
     */
    if ($report->getNumOfCvesWithTag() == 0) {
        continue;
    }

    /**
     * Get the current / last report state of packages applicable CVEs
     * with enabled CveTag.
    */
    $hostId = $host->getId();
    $taggedCves = $cvesManager->getCvesNamesForHost(
        $hostId,
        true
    );

    if(empty($taggedCves)) {
        continue;
    }

    /**
     * Ensure host is in any group.
     */
    $hostGroups = $hostGroupsManager->getHostGroupsByHost($host);

    if (empty($hostGroups)) {
        continue;
    }

    foreach ($hostGroups as $group) {

        $groupId = $group->getId();
        $groupName = $group->getName();

        /**
         * Ensure users assigned to this group exist.
         */
        $users = $hostGroupsManager->getUsersAssignedToHostGroup($groupId);

        if (empty($users)) {
            continue;
        }

        foreach ($users as $user) {

            /**
             * Ensure user's email.
             */
            $email = $user->getEmail();

            if (empty($email)) {
                Utils::log(LOG_DEBUG, "User " . $user->getUid() . " doesn't have email set", __FILE__, __LINE__);
                continue;
            }

            /**
             * Initialize / Ensure user dict.
             */
            if (!isset($notifications[$email])) {
                $notifications[$email] = array();
            }

            /**
             * Initialize / Ensure group for this user.
             */
            if (!isset($notifications[$email][$groupId])) {
                $notifications[$email][$groupId] = array(
                    'name'  => $groupName,
                    'hosts' => array(),
                );
            }

            /**
             * Initialize host.
             */
            if (!isset($notifications[$email][$groupId]['hosts'][$hostId])) {
                $notifications[$email][$groupId]['hosts'][$hostId] = array(
                    'hostname'   => $host->getHostname(),
                    'reportId'   => $lastReportId,
                    'receivedOn' => $report->getReceivedOn(),
                    'taggedCves'  => $taggedCves,
                );
            }
            
        }
    }
}