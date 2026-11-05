<?php

require(realpath(dirname(__FILE__)) . '/../../common/Loader.php');

header("Content-Type: text/csv; charset=utf-8");

$pakiti = new Pakiti();

$hostGroupName = Utils::getHttpGetVar("hostGroup");
if ($hostGroupName == null) {
    $hostGroupName = "";
}

$_cveName = Utils::getHttpGetVar("cveName");
$_tag = Utils::getHttpGetVar("tag");
if ($_tag == null) {
    $_tag = true;
}
$_hostGroupId = $pakiti->getmanager("HostGroupsManager")->getHostGroupIdByName($hostGroupName);
$_activity = Utils::getHttpGetVar("activity");

$_notRunning = (Utils::getHttpGetVar("notRunning") == "true");

$out = fopen('php://output', 'w');

$values = array('tag', "cve", "site", "host", "os", "arch", "last_report");
fputcsv($out, $values);

if ($_notRunning) {
    $hosts = $pakiti->getManager("HostsManager")->getHosts(null, -1, -1, null, null, null, $_hostGroupId, $_activity);
    foreach ($hosts as $host) {
        $cvesNames = $pakiti->getManager("CvesManager")->getCvesNamesForHost($host->getId(), null, false);
        if (empty($cvesNames)) {
            continue;
        }
        $lastReport = $pakiti->getManager("ReportsManager")->getReportById($host->getLastReportId());
        $hostGroups = $pakiti->getManager("HostGroupsManager")->getHostGroupsByHost($host);
        foreach ($hostGroups as $hostGroup) {
            foreach ($cvesNames as $cveName) {
                if ($_cveName != null && $_cveName != $cveName) {
                    continue;
                }
                fputcsv($out, array("not-running", $cveName, $hostGroup->getName(), $host->getHostName(),
                    $host->getOsName(), $host->getArchName(), ($lastReport != null) ? $lastReport->getProcessedOn() : ""));
            }
        }
    }
    fclose($out);
    exit;
}

$hosts = $pakiti->getManager("HostsManager")->getHosts(null, -1, -1, null, $_cveName, $_tag, $_hostGroupId, $_activity);

foreach ($hosts as $host) {
    $hostGroups = $pakiti->getManager("HostGroupsManager")->getHostGroupsByHost($host);
    foreach ($hostGroups as $hostGroup) {
        $cvesNames = $pakiti->getManager("CvesManager")->getCvesNamesForHost($host->getId(), $_tag);
        foreach ($cvesNames as $cveName) {
            if ($_cveName != null && $_cveName != $cveName) {
                continue;
            }
	    $cveTags = $pakiti->getManager("CveTagsManager")->getCveTagsByCveName($cveName);

	    $lastReportId = $host->getLastReportId();
            $lastReport = $pakiti->getManager("ReportsManager")->getReportById($lastReportId);

            foreach ($cveTags as $cveTag) {
                if ($_tag != null && $_tag !== true && $_tag != $cveTag->getTagName()) {
                    continue;
                }
		$values = array();
		$values[] = $cveTag->getTagName();
                $values[] = $cveName;
                $values[] = $hostGroup->getName();
                $values[] = $host->getHostName();
                $values[] = $host->getOsName();
                $values[] = $host->getArchName();
                $values[] = $lastReport->getProcessedOn();
                fputcsv($out, $values);
            }
        }
    }
}

fclose($out);
