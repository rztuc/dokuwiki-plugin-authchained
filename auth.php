<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

/**
 * Chained authentication backend
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Philipp Nesuer <pneuser@physik.fu-berlin.de>
 */
class auth_plugin_authchained extends DokuWiki_Auth_Plugin {
   public $success = true;
   //arry with authentication plugins
   protected $chained_plugins = array();
   protected $chained_auth = NULL;

    /**
     * Constructor.
     * 
     * Loads all configured plugins or the authentication plugin of the 
     * logged in user.
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     */
   public function __construct() {
      global $conf;
       // call parent
#      parent::__constructor();

      //check if there is allready an authentication plugin selected
      if(isset($_SESSION[DOKU_COOKIE]['plugin']['authchained']['module']) && 
	 !empty($_SESSION[DOKU_COOKIE]['plugin']['authchained']['module']) )
      {
	 //get previously selected authentication plugin
	 $tmp_plugin = $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'];
	 require_once(DOKU_INC."lib/plugins/".$tmp_plugin."/auth.php");
	 $tmp_classname = "auth_plugin_".$tmp_plugin;
	 $this->chained_auth = new $tmp_classname;
      }
      else {
          //get authentication plugins
         if(isset($conf['plugin']['authchained']['authtypes'])){
	    foreach(explode(":",$conf['plugin']['authchained']['authtypes']) as 
		  $tmp_plugin){
	       require_once(DOKU_INC."lib/plugins/".$tmp_plugin."/auth.php");
   	       $tmp_classname = "auth_plugin_".$tmp_plugin;
	       $tmp_class = new $tmp_classname;
	       $tmp_module = array($tmp_plugin,$tmp_class);
   	       array_push($this->chained_plugins, $tmp_module);
   	    }
         }else{
         	 $success = false;
         }
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
     * @param   string $cap the capability to check
     * @return  bool
     */
   public function canDo($cap) {
      global $conf;
#      print_r($cap);
       if(is_null($this->chained_auth))
       {
	  foreach($this->chained_plugins as $module)
	  {
	     #echo "TEST AUTHMANAGER!!!";
	     if($module[0] == 
		$conf['plugin']['authchained']['usermanager_authtype']){
		   $module[1]->canDo($cap);
		}
	  }
	  return false;
       }
       else{
	  #echo "canDo $cap ".$this->chained_auth->canDo($cap)."\n";
	  return $this->chained_auth->canDo($cap);
       }
    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns false
     *
     * @author Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param string $type   Modification type ('create', 'modify', 'delete')
     * @param array  $params Parameters for the createUser, modifyUser or deleteUsers method. The content of this array depends on the modification type
     * @return mixed Result from the modification function or false if an event handler has canceled the action
     */
    public function triggerUserMod($type, $params) {
	 if(is_null($this->chained_auth))
             return false;
	 else
             return $this->chained_auth->triggerUserMod($type, $params);
    }

    /**
      * Forwards the result of the auth plugin of the logged in user and 
      * unsets our session variable.
     * @see     auth_logoff()
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de
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
     * @param   string $user the user name
     * @param   string $pass the clear text password
     * @return  bool
     */
    public function checkPass($user, $pass) {
        //debug
       //print_r($this->chained_plugins);
       if(is_null($this->chained_auth)) {
          foreach($this->chained_plugins as $module)
          {
	    if($module[1]->canDo('external'))
	    {
	       if($module[1]->trustExternal($user, $pass))
	       {
		  $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'] = 
   		  $module[0];
		  $this->chained_auth = $module[1];
		  return true;
	       }else{
		  if($module[1]->checkPass($user, $pass))
		  {
		     $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'] =
   		                          $module[0];
		     $this->chained_auth = $module[1];
		     return true;
		  }
	       }
	    }else{
	       if($module[1]->checkPass($user, $pass))
	       {
		  $_SESSION[DOKU_COOKIE]['plugin']['authchained']['module'] = 
				        $module[0];
		  $this->this->chained_auth = $module[1];
		  return true;
	       }
	    }
          }
       } else return $this->chained_auth->checkPass($user, $pass);
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
     * @param   string $user the user name
     * @return  array containing user data or false
     */
    public function getUserData($user) {
       //if(!$this->cando['external']) msg("no valid authorisation system in use", -1);
//       echo "TESTSETEST";
       if(is_null($this->chained_auth))
       {
	  foreach($this->chained_plugins as $module)
	  {
	     $tmp_array = $module[1]->getUserData($user);
	     if(!is_bool($tmp_array))
	       $tmp_chk_arr =array_filter($tmp_array);
	     if(!empty($tmp_chk_arr) && $tmp_array)
		return $tmp_array;
	  }
	  return false;
       }
	else
	{
	   return $this->chained_auth->getUserData($user);
	}
    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns null.
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param  string     $user
     * @param  string     $pass
     * @param  string     $name
     * @param  string     $mail
     * @param  null|array $grps
     * @return bool|null
     */
    public function createUser($user, $pass, $name, $mail, $grps = null) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not allow creation of new users", 
	     -1);
	  return null;
       }
	else{
	   //please note: users will be added to the module, to which the 
	   //current user is logged into
	   if($this->canDo('addUser')){
	      return $this->chained_auth->createUser($user, $pass, $name, $mail, 
		  $grps);
	   }else{
	      msg("authorisation method does not allow creation of new 
		 users", -1);
	      return null;
	   }
	}
     }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns false
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    public function modifyUser($user, $changes) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not allow modifying of user data", 
	     -1);
	  return false;
       }
	else{
	   //please note: users will be modified in the module, to which the 
	   //current user is logged into
	   if($this->canDo('modLogin') && $this->canDo('modPass') && 
	      $this->canDo('modName') && $this->canDo('modMail') && 
	      $this->canDo('modGroups')){
	      return $this->chained_auth->createUser($user, $changes);
	   }else{
	      msg("authorisation method does not allow modifying of user 
		 data", -1);
	      return false;
	   }
	}

    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns false
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param   array  $users
     * @return  int    number of users deleted
     */
    public function deleteUsers($users) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not allow deleting of users", 
	     -1);
	  return false;
       }
	else{
	   //please note: users will be added to the module, to which the 
	   //current user is logged into
	   if($this->canDo('delUser')){
	      return $this->chained_auth->createUser($users);
	   }else{
	      msg("authorisation method does not allow deleting of users", -1);
	      return false;
	   }
	}
    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns 0
     *
     * @author Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param  array $filter array of field/pattern pairs, empty array for no filter
     * @return int
     */
    public function getUserCount($filter = array()) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not provide user counts", 
	     -1);
	  return 0;
       }
	else{
	   //please note: users will be counted in the module, to which the 
	   //current user is logged into
	   if($this->canDo('getUserCount')){
	      return $this->chained_auth->getUserCount($filter);
	   }else{
	      msg("authorisation method does not provide user counts", -1);
	      return 0;
	   }
	}

    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns empty array
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param   int   $start     index of first user to be returned
     * @param   int   $limit     max number of users to be returned
     * @param   array $filter    array of field/pattern pairs, null for no filter
     * @return  array list of userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not support mass retrievals", 
	     -1);
	  return array();
       }
	else{
	   //please note: users will be retrieved from the module, to which the 
	   //current user is logged into
	   if($this->canDo('getUsers')){
	      return $this->chained_auth->retrieveUsers($start, $limit, $filter);
	   }else{
	      msg("authorisation method does not support mass retrievals", -1);
	      return array();
	   }
	}
    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns false
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param   string $group
     * @return  bool
     */
    public function addGroup($group) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not support independent group 
	     creation", 
	     -1);
	  return false;
       }
	else{
	   //please note: users will be added to the module, to which the 
	   //current user is logged into
	   if($this->canDo('addGroup')){
	      return $this->chained_auth->addGroup($group);
	   }else{
	      msg("authorisation method does not support independent group 
		 creation", -1);
	      return false;
	   }
	}
    }

    /**
     * Forwards the result of the auth plugin of the logged in user or 
     * returns empty array
     *
     * @author  Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param   int $start
     * @param   int $limit
     * @return  array
     */
    public function retrieveGroups($start = 0, $limit = 0) {
       if(is_null($this->chained_auth)){
	  msg("authorisation method does not support group list retrieval", 
	     -1);
	  return array();
       }
	else{
	   //please note: users will be retrieved from the module, to which the 
	   //current user is logged into
	   if($this->canDo('getGroups')){
	      return $this->chained_auth->retrieveGroups($start,$limit);
	   }else{
	      msg("authorisation method does not support group list 
		 retrieval", -1);
	      return array();
	   }
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
	  return true;
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
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser($user) {
       //print_r($this->chained_auth);
        if(is_null($this->chained_auth))
	  return $user;
       else
	  return $this->chained_auth->cleanUser($user);
    }

    /**
     * Sanitize a given groupname [OPTIONAL]
     * Forwards the result of the auth plugin of the logged in user or 
     * returns false
     *
     * @author Philipp Neuser <pneuser@physik.fu-berlin.de>
     * @param  string $group groupname
     * @return string the cleaned groupname
     */
    public function cleanGroup($group) {
       if(is_null($this->chained_auth))
       {
	  return $group;
       }
       else
	  return $this->chained_auth->cleanGroup($group);
    }


    public function useSessionCache($user) {
       global $conf;
       if(is_null($this->chained_auth))
	  return ($_SESSION[DOKU_COOKIE]['auth']['time'] >= 
	  @filemtime($conf['cachedir'].'/sessionpurge'));
       else
	  return $this->chained_auth->useSessionCache($user);
    }
}
