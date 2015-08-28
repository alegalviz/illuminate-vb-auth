<?php

namespace Rixot\Illuminate\VBAuth;

use Illuminate\Container\Container;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Http\Request;

class VBAuth
{
    /**
     * Current request object.
     *
     * @var Request
     */
    protected $request;

    /**
     * Database connection interface
     *
     * @var DB
     */
    protected $database;

    /**
     * The string containing the database tables prefix
     *
     * @var string
     */
    protected $tablePrefix;

    /**
     * The cookie hash unique to the vBulletin forum
     *
     * @var string
     */
    protected $cookieHash;

    /**
     * The prefix on all cookies set by vBulletin
     *
     * @var string
     */
    protected $cookiePrefix;

    /**
     * The length of time before a cookie times out
     *
     * @var integer
     */
    protected $cookieTimeout;

    /**
     * The default user in case of no authentication
     *
     * @var array
     */
    protected $defaultUser = [
        'userid'            => 0,
        'username'          => 'unregistered',
        'usergroupid'       => 3,
        'membergroupids'    => '',
        'sessionhash'       => '',
        'salt'              => ''
    ];

    /**
     * The forum URL
     *
     * @var string
     */
    protected $forumPath;

    /**
     * An array of the columns to be fetched from the user table containing user
     * information
     *
     * @var array
     */
    protected $userColumns;

    /**
     * An array of all known usergroups
     *
     * @var array
     */
    protected $userGroups;

    /**
     * An object containing all the relevant information about a user
     *
     * @var stdClass
     */
    protected $userInfo;

    /**
     * Create a new VBAuth instance using the package config.
     *
     * @param  array  $config
     */
    public function __construct(array $config)
    {
        $this->request = app()->make('request');
        $this->database = app()->make('db');
        $this->tablePrefix = $config['db']['table_prefix'];
        $this->cookieHash = $config['cookie']['hash'];
        $this->cookiePrefix = $config['cookie']['prefix'];
        $this->cookieTimeout = $this->query('setting')->where('varname', 'cookietimeout')->first()->value;
        $this->forumPath = $config['forum_path'];
        $this->userColumns = $config['user_columns'];
        $this->userGroups = $config['user_groups'];

        $this->setUserInfo($this->defaultUser);
        $this->authenticateSession();
    }

    /**
     * Checks if the user is in the user group passed into the function
     *
     * @param  string  $group
     * @return boolean
     */
    public function is($group)
    {
        if ($this->userInfo->userid) {
            if (array_key_exists($group, $this->userGroups)) {
                $userInfoGroups = explode(',', $this->userInfo->membergroupids);
                if (in_array($this->userGroups[$group][0], $userInfoGroups)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Attempts login based on credentials passed in
     *
     * @param  array  $credentials
     * @return boolean
     */
    public function attempt(array $credentials)
    {
        if (array_key_exists('username', $credentials) && array_key_exists('password', $credentials)
            && array_key_exists('remember_me', $credentials)) {
            $credentials = (object) $credentials;
            $user = $this->isValidLogin($credentials->username, $credentials->password);

            if ($user) {
                if ($credentials->remember_me) {
                    $this->createCookieUser($user->userid, $user->password);
                }

                $this->createSession($user->userid, $credentials->remember_me);

                return true;
            }
        }

        return false;
    }

    /**
     * Checks if the user is logged in
     *
     * @return boolean
     */
    public function isLoggedIn()
    {
        return ($this->userInfo->userid ? true : false);
    }

    /**
     * Returns an object containing the user's information
     *
     * @return stdClass
     */
    public function getUserInfo()
    {
        return $this->userInfo;
    }

    /**
     * Returns an array of all of the user's group IDs
     *
     * @return array
     */
    public function getUserGroupIDs()
    {
        $membergroupids = explode(',', $this->userInfo->membergroupids);

        if (in_array($this->userInfo->usergroupid, $membergroupids)) {
            return $membergroupids;
        }

        return [$this->userInfo->usergroupid] + $membergroupids;
    }

    /**
     * Gets the particular piece of user information passed in
     *
     * @param  string  $val
     * @return string
     */
    public function get($val)
    {
        return $this->userInfo->{$val};
    }

    /**
     * Returns the logout hash necessary to link to the vBulletin logout link
     *
     * @return string
     */
    public function getLogoutHash()
    {
        return time() . '-' . sha1(
            time() . sha1($this->userInfo->userid . sha1($this->userInfo->salt) . sha1($this->cookieHash))
        );
    }

    /**
     * Manual logout function that destroys the session in the vBulletin
     * database and destroys all cookies
     *
     * @return void
     */
    public function logout()
    {
        $this->deleteSession();
    }

    /**
     * Attempts to authenticate the user based on cookies and sessions in the
     * database
     *
     * @return boolean
     */
    protected function authenticateSession()
    {
        $userid = !empty($this->cookie('userid')) ? $this->cookie('userid') : false;
        $password = !empty($this->cookie('password')) ? $this->cookie('password') : false;
        $sessionHash = !empty($this->cookie('sessionhash')) ? $this->cookie('sessionhash') : false;

        if ($userid && $password) {
            $user = $this->isValidCookieUser($userid, $password);

            if ($user) {
                $sessionHash = $this->updateOrCreateSession($userid);
                $userinfo = $this->query('user')
                    ->where('userid', $userid)
                    ->first($this->userColumns);
                $this->setUserInfo($userinfo);
                return true;
            } else {
                return false;
            }
        } elseif ($sessionHash) {
            $session = $this->query('session')
                ->where('sessionhash', $sessionHash)
                ->where('idhash', $this->fetchIdHash())
                ->first();

            if ($session) {
                if ($session && ($session->host == $this->request->server('REMOTE_ADDR'))) {
                    $userinfo = $this->query('user')
                        ->where('userid', $session->userid)
                        ->first($this->userColumns);

                    if (!$userinfo) {
                        return false;
                    }

                    $this->setUserInfo($userinfo);
                    $this->updateOrCreateSession($userinfo->userid);

                    return true;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }

        return false;
    }

    /**
     * Checks if the user's cookies are valid
     *
     * @param  string  $userid
     * @param  string  $password
     * @return boolean
     */
    protected function isValidCookieUser($userid, $password)
    {
        $dbPass = $this->query('user')->where('userid', $userid)->first(['password'])->password;

        if ($password == md5($dbPass . $this->cookieHash)) {
            return intval($userid);
        }

        return false;
    }

    /**
     * Checks if the username and password is valid
     *
     * @param  string  $username
     * @param  string  $password
     * @return boolean
     */
    protected function isValidLogin($username, $password)
    {
        $saltAndPassword = $this->query('user')->where('username', $username)->first($this->userColumns);

        if ($saltAndPassword) {
            if ($saltAndPassword->password == (md5(md5($password) . $saltAndPassword->salt))) {
                return $saltAndPassword;
            }
        }

        return false;
    }

    /**
     * Creates the corresponding cookies if a user checks the 'remember me' box
     *
     * @param  strign $userid
     * @param  string $password
     * @return void
     */
    protected function createCookieUser($userid, $password)
    {
        $this->cookie('userid', $userid, time() + 31536000);
        $this->cookie('password', md5($password . $this->cookieHash), time() + 31536000);
    }

    /**
     * Creates a new session in the database
     *
     * @param  string  $userid
     * @param  boolean  $remember
     * @return boolean
     */
    protected function createSession($userid, $remember = true)
    {
        $hash = md5(microtime() . $userid . $this->request->server('REMOTE_ADDR'));

        $timeout = time() + $this->cookieTimeout;

        if ($remember) {
            $this->cookie('sessionhash', $hash, $timeout);
        } else {
            $this->cookie('sessionhash', $hash, 0);
        }

        $session = [
            'userid'        => $userid,
            'sessionhash'   => $hash,
            'host'          => $this->request->server('REMOTE_ADDR'),
            'idhash'        => $this->fetchIdHash(),
            'lastactivity'  => time(),
            'location'      => $this->request->server('REQUEST_URI'),
            'useragent'     => substr($this->request->server('HTTP_USER_AGENT'), 0, 100),
            'loggedin'      => 1,
        ];

        $this->query('session')
            ->where('host', $this->request->server('REMOTE_ADDR'))
            ->where('useragent', substr($this->request->server('HTTP_USER_AGENT'), 0, 100))
            ->delete();

        $this->query('session')->insert($session);

        return $hash;
    }

    /**
     * Updates or creates a new session based on existing rows in the database
     *
     * @param  string  $userid
     * @return boolean
     */
    protected function updateOrCreateSession($userid)
    {
        $sessionHash = !empty($this->cookie('sessionhash')) ? $this->cookie('sessionhash') : '';

        $activityAndHash = $this->query('session')
            ->where('userid', $userid)
            ->where('idhash', $this->fetchIdHash())
            ->where('sessionhash', $sessionHash)
            ->first(['sessionhash', 'lastactivity']);

        if ($activityAndHash) {
            if ((time() - $activityAndHash->lastactivity) < $this->cookieTimeout) {

                $updatedSession = [
                    'userid' => $userid,
                    'host' => $this->request->server('REMOTE_ADDR'),
                    'lastactivity' => time(),
                    'location' => $this->request->server('REQUEST_URI'),
                ];

                $this->query('session')
                    ->where('userid', $userid)
                    ->where('useragent', substr($this->request->server('HTTP_USER_AGENT'), 0, 100))
                    ->where('sessionhash', $this->cookie('sessionhash'))
                    ->update($updatedSession);

                return $activityAndHash->sessionhash;
            } else {
                var_dump('refreshing session');
                $newSessionHash = md5(microtime() . $userid . $this->request->server('REMOTE_ADDR'));
                $timeout = time() + $this->cookieTimeout;
                $this->cookie('sessionhash', $newSessionHash, $timeout);

                $newSession = [
                    'userid'        => $userid,
                    'sessionhash'   => $newSessionHash,
                    'host'          => $this->request->server('REMOTE_ADDR'),
                    'idhash'        => $this->fetchIdHash(),
                    'lastactivity'  => time(),
                    'location'      => $this->request->server('REQUEST_URI'),
                    'useragent'     => substr($this->request->server('HTTP_USER_AGENT'), 0, 100),
                    'loggedin'      => 1,
                ];

                $this->query('session')->insert($newSession);

                return $newSessionHash;
            }
        } else {
            return $this->createSession($userid);
        }

    }

    /**
     * Deletes the session in the database and the cookies in the browser to effectively log a user out
     *
     * @return void
     */
    protected function deleteSession()
    {
        $sessionHash = $this->cookie('sessionhash');
        $this->cookie('sessionhash', '', time() - 3600);
        $this->cookie('userid', '', time() - 3600);
        $this->cookie('password', '', time() - 3600);

        $this->query('session')
            ->where('userid', $this->userInfo->userid)
            ->where('useragent', substr($this->request->server('HTTP_USER_AGENT'), 0, 100))
            ->delete();

        $hash = md5(microtime() . 0 . $this->request->server('REMOTE_ADDR'));
        $anonymousSession = [
            'userid'        => 0,
            'sessionhash'   => $hash,
            'host'          => $this->request->server('REMOTE_ADDR'),
            'idhash'        => $this->fetchIdHash(),
            'lastactivity'  => time(),
            'location'      => $this->request->server('REQUEST_URI'),
            'useragent'     => substr($this->request->server('HTTP_USER_AGENT'), 0, 100),
            'loggedin'      => 0,
        ];

        $this->query('session')->insert($anonymousSession);
    }

    /**
     * Fetches a given user's id hash
     *
     * @param  Request  $request
     * @return string The unique ID hash to each client
     */
    protected function fetchIdHash()
    {
        return md5($this->request->server('HTTP_USER_AGENT') . $this->fetchIp());
    }

    /**
     * Fetches the shortened IP used in hashing
     *
     * @return string
     */
    protected function fetchIp()
    {
        $ip = $this->request->server('REMOTE_ADDR');
        return implode('.', array_slice(explode('.', $ip), 0, 4 -1));
    }

    /**
     * Sets the userInfo object
     *
     * @param  mixed  $userinfo
     * @return void
     */
    protected function setUserInfo($userinfo)
    {
        $this->userInfo = (object) $userinfo;
    }

    /**
     * Returns a DB query builder instance for the given table using the current
     * connection credentials.
     *
     * @param  string  $table
     * @return \Illuminate\Database\Query\Builder
     */
    protected function query($table)
    {
        return $this->database->table($this->tablePrefix . $table);
    }

    /**
     * Gets or sets a cookie value.
     *
     * @param  string  $key
     * @param  string  $value
     * @param  int  $expires
     * @return mixed
     */
    protected function cookie($key, $value = null, $expires = null)
    {
        if (!empty($value)) {
            if (empty($expires)) {
                $expires = time() + 3600;
            }

            return setcookie($this->cookiePrefix . $key, $value, $expires);
        }

        $cookie = $this->cookiePrefix . $key;

        return (isset($_COOKIE[$cookie])) ? $_COOKIE[$cookie] : null;
    }
}
