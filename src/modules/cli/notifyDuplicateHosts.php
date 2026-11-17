#!/usr/bin/php
<?php

/**
 * Detect duplicated hosts and notify Pakiti admins and HostGroup users.
 *
 * A host is stored as a new Host row whenever any of hostname, ip,
 * reporterHostname or reporterIp changes. reporterHostname is computed by
 * the server (reverse DNS of the client address), so a client whose PTR
 * record appears later (typically IPv6) ends up stored twice. This script
 * only reports such cases, it never changes or deletes anything.
 *
 * @author Tilen Krošelj
 */
require(realpath(dirname(__FILE__)) . '/../../common/Loader.php');

$shortopts = "h";

# N.B. we don't handle the config parameter here but in an included file
$longopts = array(
    "help",
    "config:",
    "dry-run",
    "no-unresolved",
);

function usage()
{
    die("Usage: notifyDuplicateHosts [-h|--help] [--config <pakiti config>] [--dry-run] [--no-unresolved]\n"
        . "  --dry-run        print the notifications instead of sending them\n"
        . "  --no-unresolved  do not report hosts whose reporter hostname could not be resolved\n");
}

class DuplicateHostsMail
{
    public function getSubject()
    {
        return 'Pakiti: duplicated hosts detected';
    }

    public function getBody($notification)
    {
        $body = "Pakiti duplicated hosts notification\n\n";

        if (!empty($notification['duplicates'])) {
            $body .= "The following hosts are stored more than once (same hostname,\n";
            $body .= "different ip / reporter hostname / reporter ip). This usually happens\n";
            $body .= "when the reverse DNS of the reporting address changes, e.g. an IPv6\n";
            $body .= "address that gets its PTR record after the first report.\n\n";

            foreach ($notification['duplicates'] as $hostname => $rows) {
                $body .= "Host: " . $hostname . "\n";
                $body .= str_repeat('-', 60) . "\n";
                $first = true;
                foreach ($rows as $row) {
                    $body .= $this->formatRow($row, $first ? " (newest)" : "");
                    $first = false;
                }
                $body .= "\n";
            }

            $body .= "Obsolete entries can be removed with:\n";
            $body .= "  php src/modules/cli/hosts.php -c delete --id=<id>\n\n";
        }

        if (!empty($notification['unresolved'])) {
            $body .= "The following hosts have a reporter hostname that is only an IP address\n";
            $body .= "(reverse DNS lookup failed). They will be stored again as a new host once\n";
            $body .= "the address resolves:\n\n";
            foreach ($notification['unresolved'] as $row) {
                $body .= "Host: " . $row['hostname'] . "\n";
                $body .= $this->formatRow($row, "");
                $body .= "\n";
            }
        }

        return $body;
    }

    private function formatRow($row, $suffix)
    {
        $out  = "  id: " . $row['id'] . $suffix . "\n";
        $out .= "    ip: " . $row['ip'] . "\n";
        $out .= "    reporter hostname: " . $row['reporterHostname'] . "\n";
        $out .= "    reporter ip: " . $row['reporterIp'] . "\n";
        $out .= "    last report: " . $row['receivedOn'] . "\n";
        $out .= "    host groups: " . (empty($row['groups']) ? "-" : implode(", ", $row['groups'])) . "\n";
        return $out;
    }
}

$opt = getopt($shortopts, $longopts);

if (isset($opt["h"]) || isset($opt["help"])) {
    usage();
}

$dryRun = isset($opt["dry-run"]);
$withUnresolved = !isset($opt["no-unresolved"]);

$hostsManager = $pakiti->getManager("HostsManager");
$reportsManager = $pakiti->getManager("ReportsManager");
$hostGroupsManager = $pakiti->getManager("HostGroupsManager");
$usersManager = $pakiti->getManager("UsersManager");

/**
 * Describe one Host row; returns array(row, hostGroupIds).
 */
function describeHost($host, $reportsManager, $hostGroupsManager)
{
    $receivedOn = "-";
    $lastReportId = $host->getLastReportId();
    if (!empty($lastReportId) && $lastReportId != -1) {
        $report = $reportsManager->getReportById($lastReportId);
        if ($report != null) {
            $receivedOn = $report->getReceivedOn();
        }
    }

    $groupIds = array();
    $groupNames = array();
    foreach ($hostGroupsManager->getHostGroupsByHost($host) as $group) {
        if ($group == null) {
            continue;
        }
        $groupIds[] = $group->getId();
        $groupNames[] = $group->getName();
    }

    return array(
        array(
            'id' => $host->getId(),
            'hostname' => $host->getHostname(),
            'ip' => $host->getIp(),
            'reporterHostname' => $host->getReporterHostname(),
            'reporterIp' => $host->getReporterIp(),
            'receivedOn' => $receivedOn,
            'groups' => $groupNames,
        ),
        $groupIds,
    );
}

/**
 * Collect findings, each with the host groups it touches.
 */
$duplicates = array();      # hostname => array(rows, groupIds)
foreach ($hostsManager->getDuplicateHosts() as $hostname => $hosts) {
    $rows = array();
    $groupIds = array();
    foreach ($hosts as $host) {
        list($row, $ids) = describeHost($host, $reportsManager, $hostGroupsManager);
        $rows[] = $row;
        $groupIds = array_merge($groupIds, $ids);
    }
    $duplicates[$hostname] = array('rows' => $rows, 'groupIds' => array_unique($groupIds));
}

$unresolved = array();      # hostId => array(row, groupIds)
if ($withUnresolved) {
    foreach ($hostsManager->getHostsWithUnresolvedReporter() as $host) {
        # already reported as a duplicate
        if (isset($duplicates[$host->getHostname()])) {
            continue;
        }
        list($row, $ids) = describeHost($host, $reportsManager, $hostGroupsManager);
        $unresolved[$host->getId()] = array('row' => $row, 'groupIds' => $ids);
    }
}

if (empty($duplicates) && empty($unresolved)) {
    exit(0);
}

/**
 * Build notifications per email address.
 */
$notifications = array();

function addRecipient(&$notifications, $user)
{
    if ($user == null) {
        return null;
    }
    $email = $user->getEmail();
    if (empty($email)) {
        Utils::log(LOG_DEBUG, "User " . $user->getUid() . " doesn't have email set", __FILE__, __LINE__);
        return null;
    }
    if (!isset($notifications[$email])) {
        $notifications[$email] = array('duplicates' => array(), 'unresolved' => array());
    }
    return $email;
}

# Admins get everything
foreach ($usersManager->getAdmins() as $admin) {
    $email = addRecipient($notifications, $admin);
    if ($email === null) {
        continue;
    }
    foreach ($duplicates as $hostname => $finding) {
        $notifications[$email]['duplicates'][$hostname] = $finding['rows'];
    }
    foreach ($unresolved as $hostId => $finding) {
        $notifications[$email]['unresolved'][$hostId] = $finding['row'];
    }
}

# HostGroup users get findings of their groups
$groupUsers = array();      # groupId => User[]
function usersOfGroup($groupId, &$groupUsers, $hostGroupsManager, $usersManager)
{
    if (!isset($groupUsers[$groupId])) {
        $groupUsers[$groupId] = array();
        foreach ($hostGroupsManager->getUsersAssignedToHostGroup($groupId) as $userId) {
            $user = $usersManager->getUserById($userId);
            if ($user != null) {
                $groupUsers[$groupId][] = $user;
            }
        }
    }
    return $groupUsers[$groupId];
}

foreach ($duplicates as $hostname => $finding) {
    foreach ($finding['groupIds'] as $groupId) {
        foreach (usersOfGroup($groupId, $groupUsers, $hostGroupsManager, $usersManager) as $user) {
            $email = addRecipient($notifications, $user);
            if ($email !== null) {
                $notifications[$email]['duplicates'][$hostname] = $finding['rows'];
            }
        }
    }
}

foreach ($unresolved as $hostId => $finding) {
    foreach ($finding['groupIds'] as $groupId) {
        foreach (usersOfGroup($groupId, $groupUsers, $hostGroupsManager, $usersManager) as $user) {
            $email = addRecipient($notifications, $user);
            if ($email !== null) {
                $notifications[$email]['unresolved'][$hostId] = $finding['row'];
            }
        }
    }
}

/**
 * Send (or print) the notifications.
 */
$mailBuilder = new DuplicateHostsMail();

foreach ($notifications as $email => $notification) {
    if (empty($notification['duplicates']) && empty($notification['unresolved'])) {
        continue;
    }

    $subject = $mailBuilder->getSubject();
    $body = $mailBuilder->getBody($notification);

    if ($dryRun) {
        print "To: " . $email . "\n";
        print "Subject: " . $subject . "\n\n";
        print $body . "\n";
        print str_repeat('=', 60) . "\n";
        continue;
    }

    if (!mail($email, $subject, $body)) {
        Utils::log(LOG_ERR, "Failed to send duplicated hosts notification to " . $email, __FILE__, __LINE__);
    }
}
