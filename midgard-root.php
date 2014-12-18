<?php
   /* Uncomment the following line if you want to get dates   */
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
?>
<[code-compat]>
<[code-global]>
<[code-init]><?php
   if ($midgard && $midgard->style == 0) {
      ?><[content]><?php
   } else {
      ?><[ROOT]><?php
   }?>
<[code-finish]>
