#!/usr/bin/php
<?php

/**
 * Auto-tag CVEs by their CVSS base score published by NVD.
 *
 * Some vulnerability sources (e.g. the Debian DSA/DLA lists) carry no severity,
 * so their CVEs are never auto-tagged from OVAL. This script reads the NVD JSON
 * 2.0 yearly feeds and tags every CVE known to Pakiti whose CVSS base score is
 * at least Config::$NVD_MIN_SCORE with Config::$NVD_TAG_NAME (modifier auto-nvd).
 *
 * - The vendor's score (the CNA that published the CVE) is preferred, NVD's own
 *   score is used when the vendor gave none. CVSS v3.1, v3.0, then v4.0.
 *   Scores from Config::$NVD_IGNORED_SOURCES (default: CISA-ADP) are skipped.
 * - CVEs that already have any tag (auto-oval, manual, disabled, ...) are left
 *   alone, so admin decisions are never overwritten.
 * - Tags are never removed, even if NVD lowers the score later.
 *
 * @author Tilen Krošelj
 */
require(realpath(dirname(__FILE__)) . '/../../common/Loader.php');

# some of the options that we can use..
$shortopts = "hv";
$longopts = array(
    "help",
    "config:",
    "from-year:",
    "feed:",
    "dry-run",
    "verbose",
);

function usage()
{
    die("Usage: tagCvesFromNvd [-h|--help] [--config <pakiti config>] [--from-year=<year>] [--feed=<url or file>]... [--dry-run] [-v|--verbose]\n"
        . "  --from-year  first yearly NVD feed to read (default " . Config::$NVD_FIRST_YEAR . ")\n"
        . "  --feed       read only this feed (URL or local .json/.json.gz file), can be repeated\n"
        . "  --dry-run    print the tags that would be stored instead of storing them\n"
        . "  --verbose    print per-feed statistics\n");
}

/**
 * Streams the items of the "vulnerabilities" array of an NVD JSON 2.0 feed.
 *
 * A yearly feed is ~300 MB of JSON, so it isn't decoded at once. The reader
 * tracks the nesting depth (ignoring braces inside strings) and decodes each
 * array item (depth 3: root object > vulnerabilities array > item) on its own.
 */
class NvdFeedReader
{
    # 1MB (Mebibyte) as we gonna read in chunks due to size - NOT ALL AT ONCE!
    const CHUNK_SIZE = 1048576;

    public static function read($path, $callback)
    {
        $fp = gzopen($path, 'rb');
        if ($fp === false) {
            throw new Exception("Cannot open " . $path);
        }

        $depth = 0;
        $inString = false;
        $escape = false;
        # collected text of the current item, null outside of an item
        $item = null;

        while (!gzeof($fp)) {
            $chunk = gzread($fp, self::CHUNK_SIZE);
            if ($chunk === false) {
                gzclose($fp);
                throw new Exception("Error reading " . $path);
            }
            $len = strlen($chunk);
            $pos = 0;
            # where the current item's text starts in this chunk
            $start = 0;

            while ($pos < $len) {
                if ($escape) {
                    $escape = false;
                    $pos++;
                    continue;
                }
                if ($inString) {
                    # jump to next interesting character as everything between is characters, string..
                    $pos += strcspn($chunk, "\"\\", $pos);
                    if ($pos >= $len) {
                        break;
                    }
                    if ($chunk[$pos] == '\\') {
                        $escape = true;
                    } else {
                        $inString = false;
                    }
                    $pos++;
                    continue;
                }

                #DETERMINING JSON STRUCTURE (depth too)
                # parser is not inside string, therefore is determining JSON structure.
                $pos += strcspn($chunk, "\"{}[]", $pos);
                if ($pos >= $len) {
                    break;
                }
                $c = $chunk[$pos];
                if ($c == '"') {
                    $inString = true;
                } elseif ($c == '{' || $c == '[') {
                    $depth++;
                    if ($depth == 3 && $c == '{') {
                        $item = '';
                        #start collecting vulnerability entry information
                        $start = $pos;
                    }
                } else {
                    if ($depth == 3 && $c == '}' && $item !== null) {
                        $json = $item . substr($chunk, $start, $pos - $start + 1);
                        $item = null;
                        $entry = json_decode($json, true);
                        if (is_array($entry) && isset($entry['cve'])) {
                            call_user_func($callback, $entry['cve']);
                        } else {
                            Utils::log(LOG_WARNING, "Skipping undecodable NVD entry in " . $path, __FILE__, __LINE__);
                        }
                    }
                    $depth--;
                }
                $pos++;
            }

            if ($item !== null) {
                $item .= substr($chunk, $start);
            }
        }
        gzclose($fp);

        if ($depth != 0) {
            throw new Exception("Truncated or malformed feed " . $path);
        }
    }
}

/**
 * Readable name of a score source. The feed identifies sources by an email
 * or a UUID; the UUIDs of the frequent ones are listed here, others are
 * shown as they are.
 */
function sourceName($source, $type)
{
    $names = array(
        'nvd@nist.gov' => 'NVD',
        '134c704f-9b21-4f2e-91b3-4a467353bcc0' => 'CISA-ADP',
        '416baaa9-dc9f-4396-8d5f-8c081fb06d67' => 'kernel.org',
    );
    if (isset($names[$source])) {
        return $names[$source];
    }
    return $type == 'Primary' ? 'NVD' : $source;
}

/**
 * Returns the CVSS metric to use for a CVE, or null when it has none:
 * 1. the vendor's score (the CNA that published the CVE, its sourceIdentifier),
 * 2. NVD's own score (type Primary), when the vendor gave none,
 * 3. any other score (e.g. another CNA), when neither gave one.
 * Within each: CVSS v3.1, v3.0, then v4.0. CVSS v2 is ignored, it has no
 * "critical" rating. Scores from Config::$NVD_IGNORED_SOURCES are skipped.
 */
function pickCvss($cve)
{
    if (empty($cve['metrics']) || !is_array($cve['metrics'])) {
        return null;
    }
    $ignored = is_array(Config::$NVD_IGNORED_SOURCES) ? Config::$NVD_IGNORED_SOURCES : array();
    $cna = isset($cve['sourceIdentifier']) ? $cve['sourceIdentifier'] : null;

    $matchers = array(
        function ($metric) use ($cna) {
            return $cna !== null && isset($metric['source']) && $metric['source'] == $cna;
        },
        function ($metric) {
            return isset($metric['type']) && $metric['type'] == 'Primary';
        },
        function ($metric) {
            return true;
        },
    );

    foreach ($matchers as $matches) {
        foreach (array('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40') as $key) {
            if (empty($cve['metrics'][$key])) {
                continue;
            }
            foreach ($cve['metrics'][$key] as $metric) {
                if (!isset($metric['cvssData']['baseScore'])) {
                    continue;
                }
                if (isset($metric['source']) && in_array($metric['source'], $ignored)) {
                    continue;
                }
                if ($matches($metric)) {
                    return array(
                        'score' => (float) $metric['cvssData']['baseScore'],
                        'version' => isset($metric['cvssData']['version']) ? $metric['cvssData']['version'] : '?',
                        'source' => isset($metric['source']) ? $metric['source'] : '?',
                        'type' => isset($metric['type']) ? $metric['type'] : '?',
                    );
                }
            }
        }
    }
    return null;
}

/**
 * Downloads a URL to a temporary file (the feeds are too big to keep in memory).
 * Uses the outgoing proxy from the configuration if enabled.
 */
function downloadToTempFile($url)
{
    $tmp = tempnam(sys_get_temp_dir(), 'pakiti-nvd-');
    if ($tmp === false) {
        throw new Exception("Cannot create a temporary file");
    }

    $opts = array('http' => array('method' => 'GET', 'timeout' => 300, 'user_agent' => 'pakiti-server'));
    if (Config::$ENABLE_OUTGOING_PROXY == 1) {
        $opts['http']['proxy'] = Config::$OUTGOING_PROXY;
        $opts['http']['request_fulluri'] = true;
    }

    $in = @fopen($url, 'rb', false, stream_context_create($opts));
    if ($in === false) {
        unlink($tmp);
        $error = error_get_last();
        throw new Exception("Cannot download " . $url . ": " . ($error ? $error['message'] : 'unknown error'));
    }
    $out = fopen($tmp, 'wb');
    $copied = stream_copy_to_stream($in, $out);
    fclose($in);
    fclose($out);
    if ($copied === false || $copied == 0) {
        unlink($tmp);
        throw new Exception("Empty download from " . $url);
    }
    return $tmp;
}

$opt = getopt($shortopts, $longopts);

if (isset($opt["h"]) || isset($opt["help"])) {
    usage();
}

$dryRun = isset($opt["dry-run"]);
$verbose = isset($opt["v"]) || isset($opt["verbose"]);

if (isset($opt["feed"])) {
    $feeds = is_array($opt["feed"]) ? $opt["feed"] : array($opt["feed"]);
} else {
    $toYear = (int) date("Y");
    $fromYear = isset($opt["from-year"]) ? (int) $opt["from-year"] : (int) Config::$NVD_FIRST_YEAR;
    if ($fromYear < 1999 || $fromYear > $toYear) {
        die("Invalid --from-year value\n");
    }
    $feeds = array();
    for ($year = $fromYear; $year <= $toYear; $year++) {
        $feeds[] = sprintf(Config::$NVD_FEED_URL, $year);
    }
}

$tagName = Config::$NVD_TAG_NAME;
$minScore = (float) Config::$NVD_MIN_SCORE;
if (!in_array($tagName, Config::$TAGS)) {
    fwrite(STDERR, "Warning: tag " . $tagName . " is not listed in Config::\$TAGS\n");
}

$cveTagsManager = $pakiti->getManager("CveTagsManager");

# CVEs known to Pakiti, and CVEs that already have a tag (never touched)
$known = array_flip($pakiti->getManager("CvesManager")->getCvesNames());
$tagged = array_flip($cveTagsManager->getCveNames());

$total = 0;
$failed = false;

foreach ($feeds as $feed) {
    $stats = array('read' => 0, 'known' => 0, 'alreadyTagged' => 0, 'noScore' => 0, 'tagged' => 0);
    $isUrl = preg_match('#^https?://#i', $feed) === 1;

    try {
        $path = $isUrl ? downloadToTempFile($feed) : $feed;
    } catch (Exception $e) {
        Utils::log(LOG_ERR, $e->getMessage(), __FILE__, __LINE__);
        fwrite(STDERR, $e->getMessage() . "\n");
        $failed = true;
        continue;
    }

    try {
        NvdFeedReader::read($path, function ($cve) use (&$stats, &$known, &$tagged, &$total, $cveTagsManager, $tagName, $minScore, $dryRun) {
            $stats['read']++;
            if (empty($cve['id']) || !isset($known[$cve['id']])) {
                return;
            }
            $stats['known']++;
            if (isset($tagged[$cve['id']])) {
                $stats['alreadyTagged']++;
                return;
            }
            if (isset($cve['vulnStatus']) && $cve['vulnStatus'] == 'Rejected') {
                return;
            }
            $cvss = pickCvss($cve);
            if ($cvss === null) {
                $stats['noScore']++;
                return;
            }
            if ($cvss['score'] < $minScore) {
                return;
            }

            $reason = sprintf("Auto-tagged from NVD - CVSS %s %.1f (%s)", $cvss['version'], $cvss['score'],
                sourceName($cvss['source'], $cvss['type']));

            $cveTag = new CveTag();
            $cveTag->setCveName($cve['id']);
            $cveTag->setTagName($tagName);
            $cveTag->setReason($reason);
            $cveTag->setInfoUrl("https://nvd.nist.gov/vuln/detail/" . $cve['id']);
            $cveTag->setModifier('auto-nvd');
            $cveTag->setEnabled(1);

            if ($dryRun) {
                print $cve['id'] . "\t" . $tagName . "\t" . $reason . "\n";
            } else {
                try {
                    $cveTagsManager->storeCveTag($cveTag);
                } catch (Exception $e) {
                    Utils::log(LOG_WARNING, "Failed to auto-tag CVE " . $cve['id'] . ": " . $e->getMessage(), __FILE__, __LINE__);
                    return;
                }
            }
            # a CVE can appear in more than one feed
            $tagged[$cve['id']] = true;
            $stats['tagged']++;
            $total++;
        });
    } catch (Exception $e) {
        Utils::log(LOG_ERR, "Failed to process NVD feed " . $feed . ": " . $e->getMessage(), __FILE__, __LINE__);
        fwrite(STDERR, "Failed to process " . $feed . ": " . $e->getMessage() . "\n");
        $failed = true;
    }

    if ($isUrl) {
        unlink($path);
    }

    if ($verbose) {
        fwrite(STDERR, sprintf("%s: %d CVEs read, %d known to Pakiti, %d already tagged, %d without CVSS v3/v4, %d tagged\n",
            $feed, $stats['read'], $stats['known'], $stats['alreadyTagged'], $stats['noScore'], $stats['tagged']));
    }
}

Utils::log(LOG_INFO, ($dryRun ? "[dry-run] " : "") . "NVD auto-tagging: " . $total . " CVEs tagged " . $tagName, __FILE__, __LINE__);
if ($verbose) {
    fwrite(STDERR, ($dryRun ? "[dry-run] " : "") . "Total: " . $total . " CVEs tagged " . $tagName . "\n");
}

exit($failed ? 1 : 0);
