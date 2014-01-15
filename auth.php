<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
* Chained authentication backend
*
* @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
* @author     Philipp Neuser <pneuser@physik.fu-berlin.de>
* @author     Christian Marg <marg@rz.tu-clausthal.de>
* 
* Based on "Chained authentication backend"
* by Grant Gardner <grant@lastweekend.com.au>
* see https://www.dokuwiki.org/auth:ggauth
*
*/
class auth_plugin_authchained extends DokuWiki_Auth_Plugin {
    public $success = true;
    //array with authentication plugins
    protected $chained_plugins = array();
    protected $chained_auth = NULL;
    protected $usermanager_auth = NULL;

    /**
    * Constructor.
    * 
    * Loads all configured plugins or the authentication plugin of the 
    * logged in user.
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    */
    public function __construct() {
        global $conf;
        // call parent
        #      parent::__constructor();

        //check if there is already an authentication plugin selected
        if(     isset($_SESSION[DOKU_COOKIE]['plugin']['authchained']['module']) && 
                !empty($_SESSION[DOKU_COOKIE]['plugin']['authchained']['module']) ) {

            //get previously selected authentication plugin
            $this->chained_auth =& plugin_load('auth',$_SESSION[DOKU_COOKIE]['plugin']['authchained']['module']);
            if ( is_null($this->chained_auth) || !$this->chained_auth->success ) {
                $this->success = false;
            }
        } else {
            //get authentication plugins
            if($this->getConf('authtypes')){
                foreach(explode(":",$this->getConf('authtypes')) as $tmp_plugin){
                    $tmp_class =& plugin_load('auth',$tmp_plugin);

                    if ( !is_null($tmp_class) || $tmp_class->success ) {
                        $tmp_module = array($tmp_plugin,$tmp_class);
                        array_push($this->chained_plugins, $tmp_module);
                    } else {
                        msg("Problem constructing $tmp_plugin",-1);
                        $this->success = false;
                    }
                }
            } else {
                $success = false;
            }
        }

        // If defined, instantiate usermanager authtype.
        // No need to check for duplicates, "plugin_load" does that for us.
        if($this->getConf('usermanager_authtype')){
            $this->usermanager_auth =& plugin_load('auth',$this->getConf('usermanager_authtype'));
            if(is_null($this->usermanager_auth) || !$this->usermanager_auth->success ) {
                    msg("Problem constructing usermanager authtype: ".$this->getConf('usermanager_authtype'),-1);
                    $this->success = false;
            }
        } else { 
            $this->usermanager_auth =& $this->chained_auth;
        }

        //debug
        //      print_r($chained_plugins);
    }

    /**
    * Forwards the authentication to configured authplugins.
    * Returns true, if the usermanager authtype has the capability and no user 
    * is logged in.
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   string $cap the capability to check
    * @return  bool
    */
    public function canDo($cap) {
        global $ACT;
        #      print_r($cap);
        if(is_null($this->chained_auth)) {
            if (!is_null($this->usermanager_auth)) {
                return $this->usermanager_auth->canDo($cap);
            } else {
                return parent::canDo($cap);
            }
        } else {
            switch($cap) {
                case 'Profile':
                case 'logoff':
                    //Depends on current user.
                    return $this->chained_auth->canDo($cap);
                case 'UserMod':
                case 'addUser':
                case 'delUser':
                case 'getUsers':
                case 'getUserCount':
                case 'getGroups':
                    //Depends on the auth for use with user manager
                    return $this->usermanager_auth->canDo($cap);
                case 'modPass':
                case 'modName':
                case 'modLogin':
                case 'modGroups':
                case 'modMail':
                    /**
                    * Use request attributes to guess whether we are in the Profile or UserManager
                    * and return the appropriate auth capabilities
                    */
                    if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
                        return $this->usermanager_auth->canDo($cap);
                    } else {
                        // assume we want profile info.
                        return $this->chained_auth->canDo($cap);
                    }
// I don't know how to handle "external" in this context yet.
// Is it in any way sensible to mix regular auth with external auth? 
//                case 'external':
//                    //We are external if one of the chains is valid for external use 
//                    return $this->trustExternal($_REQUEST['u'],$_REQUEST['p'],$_REQUEST['r']);
                default:
                    //Everything else (false)
                    return parent::canDo($cap);
            }
            #echo "canDo $cap ".$this->chained_auth->canDo($cap)."\n";
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user and 
    * unsets our session variable.
    * @see     auth_logoff()
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    */
    public function logOff() {
        if(!is_null($this->chained_auth)) 
            $this->chained_auth->logOff();
        unset($_SESSION[DOKU_COOKIE]['plugin']['authchained']['module']);
    }

    /**
    * Do all authentication [ OPTIONAL ]
    * If the current plugin is external, be external.
    *
    * @see     auth_login()
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    *
    * @param   string  $user    Username
    * @param   string  $pass    Cleartext Password
    * @param   bool    $sticky  Cookie should not expire
    * @return  bool             true on successful auth
    */
    public function trustExternal($user, $pass, $sticky = false) {
        if(!is_null($this->chained_auth) && $this->chained_auth->canDo('external'))
            $this->chained_auth->trustExternal($user, $pass, $sticky);
    }

    /**
    * Check user+password [ MUST BE OVERRIDDEN ]
    *
    * Checks if the given user exists in one of the plugins and checks 
    * against the given password. The first plugin returning true becomes 
    * auth plugin of the user session.
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   string $user the user name
    * @param   string $pass the clear text password
    * @return  bool
    */
    public function checkPass($user, $pass) {
        //debug
        //print_r($this->chained_plugins);
        if(is_null($this->chained_auth)) {
            foreach($this->chained_plugins as $module) {
                if($module[1]->canDo('external')) {
                    if($module[1]->trustExternal($user, $pass)) {
                        $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'] = $module[0];
                        $this->chained_auth = $module[1];
                        return true;
                    } else {
                        if($module[1]->checkPass($user, $pass)) {
                            $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'] = $module[0];
                            $this->chained_auth = $module[1];
                            return true;
                        }
                    }
                } else {
                    if($module[1]->checkPass($user, $pass)) {
                        $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'] = $module[0];
                        $this->chained_auth = $module[1];
                        return true;
                    }
                }
            }
        } else {
            return $this->chained_auth->checkPass($user, $pass);
        }
        return false;
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * checks all plugins if the users exists. The first plugin returning 
    * data is used. 
    *
    * name string  full name of the user
    * mail string  email addres of the user
    * grps array   list of groups the user is in
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   string $user the user name
    * @return  array containing user data or false
    */
    public function getUserData($user) {
        global $ACT;
        //if(!$this->cando['external']) msg("no valid authorisation system in use", -1);
        //       echo "TESTSETEST";
	
        //print_r($this->chained_auth);
        if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
            if(!is_null($this->usermanager_auth))
                return $this->usermanager_auth->getUserData($user);
	}

        if(is_null($this->chained_auth)) {
            foreach($this->chained_plugins as $module) {
                $tmp_array = $module[1]->getUserData($user);
                if(!is_bool($tmp_array))
                    $tmp_chk_arr =array_filter($tmp_array);
                if(!empty($tmp_chk_arr) && $tmp_array)
                    return $tmp_array;
            }
            return false;
        } else {
            return $this->chained_auth->getUserData($user);
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns null.
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   string     $user
    * @param   string     $pass
    * @param   string     $name
    * @param   string     $mail
    * @param   null|array $grps
    * @return  bool|null
    */
    public function createUser($user, $pass, $name, $mail, $grps = null) {
        if(!is_null($this->usermanager_auth) && $this->canDo('addUser')) {
            return $this->usermanager_auth->createUser($user, $pass, $name, $mail, $grps);
        } else {
            msg("authorisation method does not allow creation of new users", -1);
            return null;
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns false
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   string $user    nick of the user to be changed
    * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
    * @return  bool
    */
    public function modifyUser($user, $changes) {
        if(!is_null($this->usermanager_auth) && $this->canDo('UserMod') ) {
            return $this->usermanager_auth->modifyUser($user, $changes);
        } else {
            msg("authorisation method does not allow modifying of user data", -1);
            return null;
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns false
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   array  $users
    * @return  int    number of users deleted
    */
    public function deleteUsers($users) {
        if(!is_null($this->usermanager_auth) && $this->canDo('delUser') ) {
            return $this->usermanager_auth->deleteUsers($users);
        }else{
            msg("authorisation method does not allow deleting of users", -1);
            return false;
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns 0
    *
    * @author Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author Christian Marg <marg@rz.tu-clausthal.de>
    * @param  array $filter array of field/pattern pairs, empty array for no filter
    * @return int
    */
    public function getUserCount($filter = array()) {
        if(!is_null($this->usermanager_auth) && $this->canDo('getUserCount') ){
            return $this->usermanager_auth->getUserCount($filter);
        } else {
            msg("authorisation method does not provide user counts", -1);
            return 0;
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns empty array
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   int   $start     index of first user to be returned
    * @param   int   $limit     max number of users to be returned
    * @param   array $filter    array of field/pattern pairs, null for no filter
    * @return  array list of userinfo (refer getUserData for internal userinfo details)
    */
    public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
        if(!is_null($this->usermanager_auth) && $this->canDo('getUsers') ) {
            //msg("RetrieveUsers is using ".get_class($this->usermanager_auth));
            return $this->usermanager_auth->retrieveUsers($start, $limit, $filter);
        } else {
            msg("authorisation method does not support mass retrievals", -1);
            return array();
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns false
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   string $group
    * @return  bool
    */
    public function addGroup($group) {
        if(!is_null($this->usermanager_auth) && $this->canDo('addGroup') ) {
            return $this->usermanager_auth->addGroup($group);
        } else {
            msg("authorisation method does not support independent group creation", -1);
            return false;
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns empty array
    *
    * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author  Christian Marg <marg@rz.tu-clausthal.de>
    * @param   int $start
    * @param   int $limit
    * @return  array
    */
    public function retrieveGroups($start = 0, $limit = 0) {
        if(!is_null($this->usermanager_auth) && $this->canDo('getGroups') ) {
                return $this->usermanager_auth->retrieveGroups($start,$limit);
        } else {
            msg("authorisation method does not support group list retrieval", -1);
            return array();
        }
    }

    /**
    * Forwards the result of the auth plugin of the logged in user or 
    * returns true
    *
    * @return bool
    */
    public function isCaseSensitive() {
        if(is_null($this->chained_auth))
            return parent::isCaseSensitive();
        else
            return $this->chained_auth->isCaseSensitive();
    }

    /**
    * Sanitize a given username [OPTIONAL]
    * Forwards the result of the auth plugin of the logged in user or 
    * returns false
    *
    *
    * @author Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author Christian Marg <marg@rz.tu-clausthal.de>
    * @param  string $user username
    * @return string the cleaned username
    */
    public function cleanUser($user) {
        global $ACT;
        //print_r($this->chained_auth);
        if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
            if(!is_null($this->usermanager_auth))
                return $this->usermanager_auth->cleanUser($user);
        } else {
            if(!is_null($this->chained_auth))
                return $this->chained_auth->cleanUser($user);
        }
        return parent::cleanUser($user);
    }

    /**
    * Sanitize a given groupname [OPTIONAL]
    * Forwards the result of the auth plugin of the logged in user or 
    * returns false
    *
    * @author Philipp Neuser <pneuser@physik.fu-berlin.de>
    * @author Christian Marg <marg@rz.tu-clausthal.de>
    * @param  string $group groupname
    * @return string the cleaned groupname
    */
    public function cleanGroup($group) {
        global $ACT;
        if ($ACT == "admin" && $_REQUEST['page']=="usermanager") {
            if(!is_null($this->usermanager_auth))
                return $this->usermanager_auth->cleanGroup($group);
        } else {
            if(!is_null($this->chained_auth))
                return $this->chained_auth->cleanGroup($group);
        }
        return parent::cleanGroup($group);
    }


    public function useSessionCache($user) {
        global $conf;
        if(is_null($this->chained_auth))
            return parent::useSessionCache($user);
        else
            return $this->chained_auth->useSessionCache($user);
    }

}
