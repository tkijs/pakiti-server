<?php

/**
 * @author Michal Prochazka
 * @author Jakub Mlcak
 */
class HostsManager extends DefaultManager
{
    /**
     * Create if not exist, else update and set id
     * @return false if already exist
     */
    public function storeHost(Host $host)
    {
        Utils::log(LOG_DEBUG, "Storing the host", __FILE__, __LINE__);
        if ($host == null) {
            Utils::log(LOG_ERR, "Exception", __FILE__, __LINE__);
            throw new Exception("Host object is not valid");
        }

        $new = false;
        $dao = $this->getPakiti()->getDao("Host");
        $host->setId($dao->getIdByHostnameIpReporterHostnameReporterIp($host->getHostname(), $host->getIp(), $host->getReporterHostname(), $host->getReporterIp()));
        if ($host->getid() == -1) {
            # Host is missing, so store it
            $dao->create($host);
            $new = true;
        } else {
            $dao->update($host);
        }
        return $new;
    }

    /**
     * Get host ID by hostname, ip, reporterHostname and reporterIp
     */
    public function getHostId($hostname, $ip, $reporterHostname, $reporterIp)
    {
        Utils::log(LOG_DEBUG, "Getting the host ID", __FILE__, __LINE__);
        return $this->getPakiti()->getDao("Host")->getIdByHostnameIpReporterHostnameReporterIp($hostname, $ip, $reporterHostname, $reporterIp);
    }

    /**
     * Get host by ID
     */
    public function getHostById($id, $userId = -1)
    {
        Utils::log(LOG_DEBUG, "Getting the host[$id]", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        return $dao->getById($id, $userId);
    }

    /**
     * Get hosts sharing the same hostname, as array(hostname => Host[]),
     * each list ordered newest report first.
     * With $userId only hosts accessible to that user are returned, so a list
     * can have a single entry when the other copies are in foreign host groups.
     */
    public function getDuplicateHosts($userId = -1)
    {
        Utils::log(LOG_DEBUG, "Getting duplicate hosts", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        $duplicates = array();
        foreach ($dao->getDuplicateHostnames() as $hostname) {
            $hosts = array();
            foreach ($dao->getIdsByHostname($hostname) as $id) {
                $host = $dao->getById($id, $userId);
                if ($host != null) {
                    $hosts[] = $host;
                }
            }
            if (count($hosts) > ($userId == -1 ? 1 : 0)) {
                $duplicates[$hostname] = $hosts;
            }
        }
        return $duplicates;
    }

    /**
     * Get hosts whose reporterHostname is only the reporter IP (failed reverse DNS)
     */
    public function getHostsWithUnresolvedReporter($userId = -1)
    {
        Utils::log(LOG_DEBUG, "Getting hosts with unresolved reporter hostname", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        $hosts = array();
        foreach ($dao->getUnresolvedReporterIds() as $id) {
            $host = $dao->getById($id, $userId);
            if ($host != null) {
                $hosts[] = $host;
            }
        }
        return $hosts;
    }

    /**
     * Other Host rows with the same hostname as $host (accessible to $userId)
     */
    public function getOtherHostsWithSameHostname(Host $host, $userId = -1)
    {
        $dao = $this->getPakiti()->getDao("Host");
        $hosts = array();
        foreach ($dao->getIdsByHostname($host->getHostname()) as $id) {
            if ($id == $host->getId()) {
                continue;
            }
            $other = $dao->getById($id, $userId);
            if ($other != null) {
                $hosts[] = $other;
            }
        }
        return $hosts;
    }

    /**
     * Number of Host rows with the given hostname (regardless of access)
     */
    public function getHostsCountByHostname($hostname)
    {
        return count($this->getPakiti()->getDao("Host")->getIdsByHostname($hostname));
    }

    /**
     * Describe what merging host $fromId into host $intoId would do.
     * Returns array with 'errors' (non-empty = the merge is not allowed) and,
     * when allowed, the details shown to the user before confirming.
     *
     * Rules: both hosts exist and are accessible to $userId, they have the same
     * hostname and $intoId is the newest entry of that hostname (the one the
     * feeder matches new reports to).
     */
    public function getMergePlan($fromId, $intoId, $userId = -1)
    {
        $plan = array('errors' => array());
        $fromId = (int)$fromId;
        $intoId = (int)$intoId;

        if ($fromId <= 0 || $intoId <= 0 || $fromId == $intoId) {
            $plan['errors'][] = "Choose two different hosts to merge.";
            return $plan;
        }

        $dao = $this->getPakiti()->getDao("Host");
        $from = $dao->getById($fromId, $userId);
        $into = $dao->getById($intoId, $userId);
        if ($from == null || $into == null) {
            $plan['errors'][] = "Host #" . ($from == null ? $fromId : $intoId) . " doesn't exist or access denied.";
            return $plan;
        }
        if ($from->getHostname() != $into->getHostname()) {
            $plan['errors'][] = "Hosts #$fromId and #$intoId have different hostnames.";
            return $plan;
        }
        $ids = $dao->getIdsByHostname($into->getHostname());
        if (empty($ids) || $ids[0] != $intoId) {
            $plan['errors'][] = "Host #$intoId is not the newest entry of " . $into->getHostname()
                . ", merge into #" . (empty($ids) ? "?" : $ids[0]) . " instead.";
            return $plan;
        }

        $reportsManager = $this->getPakiti()->getManager("ReportsManager");
        $hostGroupsManager = $this->getPakiti()->getManager("HostGroupsManager");
        $usersManager = $this->getPakiti()->getManager("UsersManager");

        $lastReport = function ($host) use ($reportsManager) {
            $id = $host->getLastReportId();
            if (empty($id) || $id == -1) {
                return null;
            }
            $report = $reportsManager->getReportById($id);
            return ($report == null ? null : $report->getReceivedOn());
        };
        $groupNames = function ($host) use ($hostGroupsManager) {
            $names = array();
            foreach ($hostGroupsManager->getHostGroupsByHost($host) as $g) {
                if ($g != null) {
                    $names[] = $g->getName();
                }
            }
            return $names;
        };

        $intoUserIds = $dao->getDirectlyAssignedUserIds($intoId);
        $usersToCopy = array();
        foreach ($dao->getDirectlyAssignedUserIds($fromId) as $uid) {
            if (in_array($uid, $intoUserIds)) {
                continue;
            }
            $user = $usersManager->getUserById($uid);
            $usersToCopy[] = ($user == null ? "#$uid" : $user->getName() . " (" . $user->getUid() . ")");
        }

        $plan['from'] = $from;
        $plan['into'] = $into;
        $plan['fromLastReport'] = $lastReport($from);
        $plan['intoLastReport'] = $lastReport($into);
        $plan['fromReports'] = $dao->getReportsSummary($fromId);
        $plan['intoReports'] = $dao->getReportsSummary($intoId);
        $plan['usersToCopy'] = $usersToCopy;
        $plan['fromPkgs'] = $dao->getInstalledPkgsCount($fromId);
        $plan['intoPkgs'] = $dao->getInstalledPkgsCount($intoId);
        $plan['fromGroups'] = $groupNames($from);
        $plan['intoGroups'] = $groupNames($into);
        return $plan;
    }

    /**
     * Merge host $fromId into host $intoId (see getMergePlan() for the rules).
     *
     * Steps 1-3 run in one transaction, step 4 verifies the result after the
     * commit. Returns array('plan' => ..., 'steps' => array(1 => text, ...)).
     * On failure throws an Exception whose code is the failed step (0 = the
     * merge was not allowed); a failure in steps 0-3 changed nothing.
     */
    public function mergeHosts($fromId, $intoId, $userId = -1)
    {
        $plan = $this->getMergePlan($fromId, $intoId, $userId);
        if (!empty($plan['errors'])) {
            throw new Exception(implode(" ", $plan['errors']), 0);
        }
        $from = $plan['from']->getId();
        $into = $plan['into']->getId();

        Utils::log(LOG_INFO, "Merging host [id=$from] into host [id=$into, hostname=" . $plan['into']->getHostname() . "]", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        $db = $this->getPakiti()->getManager("DbManager");
        $steps = array();
        $step = 1;

        $db->begin();
        try {
            $moved = $dao->moveReports($from, $into);
            $steps[1] = "$moved report" . ($moved != 1 ? "s" : "") . " moved to #$into";

            $step = 2;
            $copied = $dao->copyDirectlyAssignedUsers($from, $into);
            $steps[2] = ($copied > 0 ? "$copied user assignment" . ($copied != 1 ? "s" : "") . " copied to #$into" : "Nothing to copy");

            $step = 3;
            if ($dao->delete($from) != 1) {
                throw new Exception("Host #$from could not be deleted (already removed?)");
            }
            $steps[3] = "#$from removed with its " . $plan['fromPkgs'] . " outdated package rows";

            $db->commit();
        } catch (Exception $e) {
            $db->rollback();
            Utils::log(LOG_ERR, "Merging host [id=$from] into [id=$into] failed in step $step: " . $e->getMessage(), __FILE__, __LINE__);
            throw new Exception($e->getMessage(), $step);
        }

        $step = 4;
        $left = array_filter($dao->countReferences($from));
        if (!empty($left)) {
            $what = array();
            foreach ($left as $table => $count) {
                $what[] = "$table: $count";
            }
            throw new Exception("Merged, but rows still reference #$from (" . implode(", ", $what) . ")", 4);
        }
        $steps[4] = "Nothing references #$from anymore";

        return array('plan' => $plan, 'steps' => $steps);
    }

    /**
     * Get hosts
     */
    public function getHosts($orderBy = null, $orderByDirection = null, $pageSize = -1, $pageNum = -1, $search = null, $cveName = null, $tag = null, $hostGroupId = -1, $activity = null, $pkgId = -1, $userId = -1, $directlyAssignedToUser = false)
    {
        Utils::log(LOG_DEBUG, "Getting hosts", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        $hostsIds = $dao->getHostsIds($orderBy, $orderByDirection, $pageSize, $pageNum, $search, $cveName, $tag, $hostGroupId, $activity, $pkgId, $userId, $directlyAssignedToUser);
        
        $hosts = array();
        foreach ($hostsIds as $hostId) {
            array_push($hosts, $this->getHostById($hostId));
        }
        return $hosts;
    }

    /**
     * Get hosts IDs
     */
    public function getHostsIds($orderBy = null, $pageSize = -1, $pageNum = -1, $search = null, $cveName = null, $tag = null, $hostGroupId = -1, $activity = null, $pkgId = -1, $userId = -1, $directlyAssignedToUser = false)
    {
        Utils::log(LOG_DEBUG, "Getting hosts IDs", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        return $dao->getHostsIds($orderBy, null, $pageSize, $pageNum, $search, $cveName, $tag, $hostGroupId, $activity, $pkgId, $userId, $directlyAssignedToUser);
    }

    /**
     * Get hosts count
     */
    public function getHostsCount($search = null, $cveName = null, $tag = null, $hostGroupId = -1, $activity = null, $pkgId = -1, $userId = -1)
    {
        Utils::log(LOG_DEBUG, "Getting hosts count", __FILE__, __LINE__);
        return sizeof($this->getPakiti()->getDao("Host")->getHostsIds(null, null, -1, -1, $search, $cveName, $tag, $hostGroupId, $activity, $pkgId, $userId));
    }

    /**
     * Delete host by ID
     */
    public function deleteHost($id)
    {
        Utils::log(LOG_DEBUG, "Delete host[$id]", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        return $dao->delete($id);
    }

    /**
     * Recalculate CVEs count for host by ID
     */
    public function recalculateCvesCountForHost($hostId)
    {
        Utils::log(LOG_DEBUG, "Recalculating numOfCves for Host[".$hostId."]", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        $host = $this->getHostById($hostId);
        if ($host == null) {
            # Host might have been deleted, skip silently
            Utils::log(LOG_WARNING, "Host[".$hostId."] doesn't exist, skipping", __FILE__, __LINE__);
            return;
        }
        # Get number of CVEs
        $cvesManager = $this->getPakiti()->getManager("CvesManager");
        $host->setNumOfCves(sizeof($cvesManager->getCvesNamesForHost($host->getId(), null)));
        $host->setNumOfCvesWithTag(sizeof($cvesManager->getCvesNamesForHost($host->getId(), true)));

        $dao->update($host);
    }

    /**
     * Recalculate CVEs count for each host
     */
    public function recalculateCvesCountForEachHost()
    {
        Utils::log(LOG_DEBUG, "Recalculating numOfCves for each host", __FILE__, __LINE__);
        $dao = $this->getPakiti()->getDao("Host");
        $ids = $dao->getHostsIds();

        foreach ($ids as $id) {
            $this->recalculateCvesCountForHost($id);
        }
    }
}
