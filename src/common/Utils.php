<?php

/**
 * @author Michal Prochazka
 * @author Jakub Mlcak
 */
final class Utils
{

    /**
     * Returns delay between startTime and currentTime in long format
     */
    public static function getTimer($startTime)
    {
        return sprintf("%f", (microtime(true) - $startTime));
    }

    /**
     * Return current Pakiti version (it is stored in the src/common/Constants.php
     */
    public static function pakitiVersion()
    {
        return Constants::$PAKITI_VERSION;
    }

    /**
     * If debug is enabled, then also LOG_DEBUG messages will be logged
     */
    public static function log($priority, $msg, $file = "", $line = "")
    {
        $msg_key = "";
        /* this only works in the web-server mode! */
        if (isset($_SERVER["REMOTE_ADDR"]))
            $msg_key = $_SERVER["REMOTE_ADDR"];
        if (isset($_SERVER["REMOTE_PORT"]))
            $msg_key = $msg_key . ":" . $_SERVER["REMOTE_PORT"];

        if (Config::$DEBUG) {
            $date = date(DATE_RFC822);
            syslog($priority, "($msg_key) $date [$file:$line]: $msg");
        } else {
            if ($priority != LOG_DEBUG) {
                $date = date(DATE_RFC822);
                syslog($priority, "($msg_key) $date: $msg");
            }
        }
    }

    /**
     * Try to get the variable name in this order GET, POST
     */
    public static function getHttpVar($varName)
    {
        Utils::log(LOG_DEBUG, "Getting attribute [name=$varName] from the HTTP request", __FILE__, __LINE__);
        if (isset($_POST[$varName])) {
            return $_POST[$varName];
        } elseif (isset($_GET[$varName])) {
            return $_GET[$varName];
        } else {
            return null;
        }
    }

    /**
     * Try to get the variable name only from GET
     */
    public static function getHttpGetVar($varName)
    {
        Utils::log(LOG_DEBUG, "Getting attribute [name=$varName] from the HTTP GET request", __FILE__, __LINE__);
        if (isset($_GET[$varName])) {
            return $_GET[$varName];
        } else {
            return null;
        }
    }

    /**
     * Try to get the variable name only from POST
     */
    public static function getHttpPostVar($varName)
    {
        Utils::log(LOG_DEBUG, "Getting attribute [name=$varName] from the HTTP POST request", __FILE__, __LINE__);
        if (isset($_POST[$varName])) {
            return $_POST[$varName];
        } else {
            return null;
        }
    }

    /**
     * Get variable from the _SERVER array
     */
    public static function getServerVar($varName)
    {
        Utils::log(LOG_DEBUG, "Getting varialbe [name=$varName] from the _SERVER array", __FILE__, __LINE__);
        if (isset($_SERVER[$varName])) {
            return $_SERVER[$varName];
        }
    }

    /**
     * Removes epoch from the package version
     */
    public static function removeEpoch($pkgName)
    {
        return preg_replace('/^[0-9]+:(.*)$/', '\1', $pkgName);
    }

    /**
     * Is the package part of the kernel family (several versions can be installed side by side)?
     */
    public static function isKernelPkg($pkgName)
    {
        if (in_array($pkgName, Config::$KERNEL_PACKAGES_NAMES)) {
            return true;
        }
        $patterns = isset(Config::$KERNEL_PACKAGES_PATTERNS) ? Config::$KERNEL_PACKAGES_PATTERNS : array();
        foreach ($patterns as $pattern) {
            if (preg_match("/$pattern/", $pkgName) == 1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Canonical key identifying a package (name, version-release without epoch, arch),
     * used to match packages against the running-kernel-pkgs hint sent by the client.
     */
    public static function kernelPkgKey($name, $version, $release, $arch)
    {
        $vr = Utils::removeEpoch(trim($version));
        if ($release !== null && $release !== "") {
            $vr .= "-" . trim($release);
        }
        return trim($name) . " " . $vr . " " . trim($arch);
    }

    /**
     * Parse the running-kernel-pkgs report header sent by the client.
     * Format: "name version arch;name version arch;..." (version may contain epoch and release)
     * @return array key => true (keys created by kernelPkgKey), empty if the header is missing
     */
    public static function parseRunningKernelPkgsHint($hint)
    {
        $keys = array();
        if ($hint === null || trim($hint) === "") {
            return $keys;
        }
        foreach (explode(";", $hint) as $entry) {
            $fields = preg_split('/\s+/', trim($entry));
            if (count($fields) != 3) {
                continue;
            }
            $keys[Utils::kernelPkgKey($fields[0], $fields[1], "", $fields[2])] = true;
        }
        return $keys;
    }

    /**
     * Does the kernel-family package belong to the running kernel?
     * The package is running if the client listed it in running-kernel-pkgs OR if it matches the
     * running kernel version (uname -r) heuristically, so a package missed by one of the methods
     * is never wrongly hidden.
     *
     * @param $name, $version, $release, $arch package as parsed by the feeder
     * @param $type packager (rpm|dpkg)
     * @param $kernel running kernel (uname -r)
     * @param $hostArch architecture of the host (uname -m)
     * @param $runningHint result of parseRunningKernelPkgsHint()
     */
    public static function isRunningKernelPkg($name, $version, $release, $arch, $type, $kernel, $hostArch = "", $runningHint = array())
    {
        if (array_key_exists(Utils::kernelPkgKey($name, $version, $release, $arch), $runningHint)) {
            return true;
        }

        $kernel = trim($kernel);
        if ($kernel === "") {
            return false;
        }

        if ($type == Constants::$PACKAGER_SYSTEM_DPKG) {
            # Debian/Ubuntu carry the kernel version in the package name, e.g. linux-image-6.1.0-18-amd64
            # Metapackages (linux-image-amd64) never match.
            return preg_match('/-' . preg_quote($kernel, '/') . '(-|$)/', $name) == 1;
        }

        # rpm: uname -r = <version>-<release>[.<arch>][+flavour|-flavour], e.g.
        #   5.14.0-427.13.1.el9_4.x86_64, 5.14.0-427.el9.aarch64+64k, 5.14.21-150500.55.39-default (SUSE)
        $versionWithoutEpoch = Utils::removeEpoch($version);
        $candidates = array($versionWithoutEpoch . "-" . $release);
        # SUSE packages have an extra rebuild counter in the release (150500.55.39.1) which is not in uname -r
        if (preg_match('/^(.*)\.[0-9]+$/', $release, $m) == 1) {
            $candidates[] = $versionWithoutEpoch . "-" . $m[1];
        }
        $archs = array();
        foreach (array($arch, $hostArch) as $a) {
            if ($a !== null && $a !== "" && $a != "noarch") {
                $archs[] = preg_quote($a, '/');
            }
        }
        $archRe = empty($archs) ? "" : "(\.(" . implode("|", $archs) . "))?";
        foreach ($candidates as $candidate) {
            if (strpos($kernel, $candidate) !== 0) {
                continue;
            }
            # The rest of uname -r must not continue the release (70.13.1 must not match 70.13.11)
            $rest = substr($kernel, strlen($candidate));
            if (preg_match('/^' . $archRe . '([+-].*|[A-Za-z]+)?$/', $rest) == 1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get stream context. Through proxy or direct connection.
     */
    public static function getStreamContext()
    {
        Utils::log(LOG_DEBUG, "Getting stream context", __FILE__, __LINE__);
        if (Config::$ENABLE_OUTGOING_PROXY == 1) {
            $opts = array('http' => array('proxy' => Config::$OUTGOING_PROXY, 'request_fulluri' => true));
            Utils::log(LOG_DEBUG, "Using outgoing proxy: " . Config::$OUTGOING_PROXY);
        } else {
            $opts = array('http' => array('method'=>"GET"));
        }
        return stream_context_create($opts);
    }

    /**
     * Get content from url.
     */
    public static function getContent($url)
    {
        Utils::log(LOG_DEBUG, "Getting content from url: ". $url, __FILE__, __LINE__);
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $content = curl_exec($ch);
        if ($content === false) {
            Utils::log(LOG_ERR, "Curl error: " . curl_error($ch), __FILE__, __LINE__);
        }
        curl_close($ch);
        return $content;
    }

    /* XXX sounds like a duplication of getContent() above */
    public static function downloadContents($url)
    {
        $contents = file_get_contents($url, NULL, stream_context_create(["http"=>["timeout"=>60*5]]));
        if ($contents === False) {
            $error = error_get_last();
            throw new Exception(sprintf("Error while getting contents (%s)", $error['message']));
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimetype = $finfo->buffer($contents);
        switch ($mimetype) {
            case "text/plain":      // Debian DSA
            case "text/xml":        // Uncompressed OVAL
            case "application/xml": // Uncompressed OVAL
                break;
            case "application/x-gzip":
            case "application/gzip":   
                $contents = gzdecode($contents);
                if ($contents === False)
                    throw new Exception("Failed to decompress gzip data");
                break;
            case "application/x-bzip2": //Compressed OVAL
                $contents = bzdecompress($contents);
                if (is_int($contents))
                    throw new Exception(snprintf("Failed to decompress bzip2 data (error: %s)", $contents, $url));
                break;
            default:
                throw new Exception(sprintf("Unknown mimetype %s", $mimetype));
        }

        return $contents;
    }

    public static function isConnectionSecure()
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off');
    }

    /**
     * Compose sql select statement
     * select, from, join, where and order could be string, string array or null
     * limit and offset could be numeric or null
     * @return sql statement
     */
    public static function sqlSelectStatement($select, $from, $join = null, $where = null, $order = null, $limit = null, $offset = null)
    {
        $sql = Utils::compose("select ", $select, ",")
            . Utils::compose("from ", $from, ",")
            . Utils::compose("", $join, "")
            . Utils::compose("where ", $where, " and")
            . Utils::compose("order by ", $order, ",")
            . Utils::compose("limit ", $limit)
            . Utils::compose("offset ", $offset);

        if ($select == null || $from == null || ($limit != null && !is_numeric($limit)) || ($offset != null && !is_numeric($offset))) {
            Utils::log(LOG_ERR, "Exception", __FILE__, __LINE__);
            throw new Exception("Select SQL statement error: $sql");
        }

        Utils::log(LOG_DEBUG, "Select SQL statement: $sql", __FILE__, __LINE__);
        return $sql;
    }

    private static function compose($mean, $string, $separator = null)
    {
        $sql = "";
        if ($string != null) {
            if (!is_array($string)) {
                $sql .= "$mean$string ";
            } else {
                if (!empty($string) && $separator !== null) {
                    $sql .= "$mean";
                    foreach ($string as $item) {
                        $sql .= "$item$separator ";
                    }
                    $length = -1 - strlen($separator);
                    $sql = substr($sql, 0, $length);
                    $sql .= " ";
                }
            }
        }
        return $sql;
    }
}
