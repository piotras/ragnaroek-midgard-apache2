<?php
   /* $Id: midgard-root-nommp.php,v 1.2 2004/05/26 08:30:44 schmitt Exp $ */
   /* This is the Midgard root file.                          */
   /* First we set up some global variables for Midgard pages */
   /* and then we start the page generation process by        */
   /* invoking a set of standard templates.                   */
   
   /* Uncomment the following line if you want to get dates 
   /* localized (replace second parameter with correct locale)*/
   /* setlocale("LC_ALL","ru_RU.KOI8-R");                     */
   
   if(!function_exists("mgd_get_midgard")) {
      die ("Midgard extension is not loaded!");
   }
   if ($midgard = mgd_get_midgard()) {
      $argc = $midgard->argc;
      $argv = $midgard->argv;
   }
   function mgd_execute_udf($variable, $selector)
   {
      $function = mgd_register_filter($selector);
      $function($variable);
   }
   function mgd_register_filter($selector, $function=NULL)
   {
      static $udf = array();

      if (is_null($function)) {
         return $udf[$selector];
      }

      if ($function == '') {
         unset($udf[$selector]);
      } else {
         $udf[$selector] = $function;
      }

      return 1;
   }
   eval('?>'.mgd_preparse(mgd_template("code-compat").'<?php '));
   eval('?>'.mgd_preparse(mgd_template("code-global").'<?php '));
   eval('?>'.mgd_preparse(mgd_template("code-init").'<?php '));


   if ($midgard && $midgard->style == 0) {
     eval('?>'.mgd_preparse(mgd_template("content").'<?php '));
   } else {
     eval('?>'.mgd_preparse(mgd_template("ROOT").'<?php '));
   }
   
   eval('?>'.mgd_preparse(mgd_template("code-finish").'<?php '));

?>
