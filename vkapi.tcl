# vkapi.tcl - Tcl VK API
#
# Copyright (c) 2016 by Konstantin Kushnir <chpock@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package require tls
package require http
package require json
package require procarg

::http::register https 443 [list apply {{args} { ::tls::socket -ssl3 false -ssl2 false -tls1 true -servername [lindex $args end-1] {*}[lrange $args 0 end-2] [lindex $args end-1] [lindex $args end] }}]
::tls::init -tls1 1

::oo::class create vkapi {

  variable app_id
  variable lang
  variable scope
  variable access_token

  variable rid
  variable response

  variable error

  constructor { args } {

    set lang 0
    set scope "friends photos audio video wall groups messages offline"

    set error [list apply {{ code msg } {
      upvar result result
      set result [dict create error [dict create error_code $code error_msg $msg]]
    }}]

    my setup {*}$args
  }

  method unknown { func args } {
    set limit_func {
      groups.getMembers {users 1000}
    }
    set o [dict create]
    for { set i 0 } { $i < [llength $args] } { incr i } {
      set key [lindex $args $i]
      if { $key ne "-callback" } {
        if { [string index $key 0] ne "-" } {
          return -code error "::vkapi::$func error: argument('$key') not properly formed - '$args'"
        }
        set key [string range $key 1 end]
      }
      dict set o $key [lindex $args [incr i]]
    }
    if { [dict exists $limit_func $func] } {
      dict set o -limit-count [lindex [dict get $limit_func $func] 1]
      dict set o -limit-field [lindex [dict get $limit_func $func] 0]
    }
    coroutine [self object]::[set myrid [incr rid]] my Request $func $o $myrid
    if { ![dict exists $o -callback] } {
      vwait [self namespace]::response($myrid)
      set result $response($myrid)
      unset response($myrid)
      return $result
    }
    return
  }

  method setup { { args {
    {-app_id       string -nodefault}
    {-scope        list   -nodefault -restrict {in {notify friends photos audio video docs notes pages status offers questions wall groups messages email notifications stats ads market offline nohttps}}}
    {-lang         string -nodefault -restrict {ru ua be en es fi de it 0 1 2 3 4 5 6 7}}
    {-access_token string -nodefault}
  }}} {
    ::procarg::parse
    if { [info exists opts(-app_id)] } {
      set app_id $opts(-app_id)
    }
    if { [info exists opts(-lang)] } {
	    set lang $opts(-lang)
    }
    if { [info exists opts(-scope)] } {
      set scope $opts(-scope)
    }
    if { [info exists opts(-access_token)] } {
      set access_token $opts(-access_token)
    }
  }

  method auth { { args {
    {-login    string -allowempty false}
    {-password string -allowempty false}
    {-callback string -nodefault}
  }}} {
    ::procarg::parse
    coroutine [self object]::[set myrid [incr rid]] my Auth [array get opts] $myrid
    {*}$return
  } 

  method Auth { o myrid } {
	  if { ![dict exists $o -callback] } {
	    dict set o -callback [list set [self namespace]::response($myrid)]
	  }
	  set cookies [dict create]
	  puts "get cookies"
	  if { [catch [list ::http::geturl "https://new.vk.com/" -command [info coroutine]] errmsg] } {
	    {*}$error -100 "error while get cookies - $errmsg"
	  } {
	    set token [yield]
	    puts "got token [::http::status $token] [::http::code $token]"
	    if { [::http::status $token] eq "error" } {
	      {*}$error -100 "error while get cookies - status: [::http::status $token], error: [::http::error $token]"
	    } elseif { [::http::status $token] ne "ok" } {
	      {*}$error -100 "error while get cookies - status: [::http::status $token]"
	    } elseif { [::http::ncode $token] ne "200" } {
	      {*}$error -100 "error while get cookies - server return code: [::http::code $token]"
	    } {
	      puts "ok"
	      foreach { key val } [::http::meta $token] {
	        if { $key ne "Set-Cookie" } continue
          set val [split [lindex [split $val "\;"] 0] =]
	        dict set cookies [string trim [lindex $val 0]] [string trim [join [lrange $val 1 end] =]]
	      }
	      puts "form query"
	      set query [dict create act login email [dict get $o -login] pass [dict get $o -password]]
	      set data [::http::data $token]
	      foreach key {_origin ip_h lg_h} {
	        puts "key: $key"
	        if { ![regexp -nocase "name=\"$key\"\\s+value=\"\(\[^\"\]+)\"" $data -> val] } continue
	        dict set query $key $val
	      }
	      unset data
	      puts "xxx"
	      if { ![dict exists $cookies remixlang] } {
	        {*}$error -100 "error while get cookies - cookie 'remixlang' not found in server response"
	      } elseif { ![dict exists $cookies remixlhk] } {
	        {*}$error -100 "error while get cookies - cookie 'remixlhk' not found in server response"
	      } elseif { ![dict exists $query _origin] } {
	        {*}$error -100 "error while get cookies - form field '_origin' not found in server response"
	      } elseif { ![dict exists $query ip_h] } {
	        {*}$error -100 "error while get cookies - form field 'ip_h' not found in server response"
	      } elseif { ![dict exists $query lg_h] } {
	        {*}$error -100 "error while get cookies - form field 'lg_h' not found in server response"
	      }
	    }
	    puts "cleanup 1"
	    ::http::cleanup $token
	    if { ![info exists result] } {
		    set cook [list]
		    dict for { key val } $cookies {
		      lappend cook "${key}=${val}"
		    }
		    puts "auth..."
	      if { [catch [list ::http::geturl "https://login.vk.com/" -command [info coroutine] -query [::http::formatQuery {*}$query] -headers [list "Cookie" [join $cook "; "]]] errmsg] } {
			    {*}$error -101 "error while auth - $errmsg"
	      } {
			    set token [yield]
	  		  if { [::http::status $token] eq "error" } {
			      {*}$error -101 "error while auth - status: [::http::status $token], error: [::http::error $token]"
			    } elseif { [::http::status $token] ne "ok" } {
			      {*}$error -101 "error while auth - status: [::http::status $token]"
			    } elseif { [::http::ncode $token] ne "302" } {
			      {*}$error -101 "error while auth - server return code: [::http::code $token]"
			    } {
			      foreach { key val } [::http::meta $token] {
			        if { $key eq "Location" } {
			          set location $val
			        }
			        if { $key ne "Set-Cookie" } continue
		          set val [split [lindex [split $val "\;"] 0] =]
			        dict set cookies [string trim [lindex $val 0]] [string trim [join [lrange $val 1 end] =]]
			      }

			    }
			    ::http::cleanup $token
	      }
	    }
	  }
	  puts "callback: [dict get $o -callback]"
    after 0 [linsert [dict get $o -callback] end $result]
    return
  }

  method Request { func o myrid } {
	  if { ![dict exists $o -callback] } {
	    dict set o -callback [list set [self namespace]::response($myrid)]
	  }
	  if { ![dict exists $o lang] } {
		  dict set o lang $lang
		}

	  if { [dict exists $o -limit-count] && [dict exists $o -limit-field] && ![dict exists $o count] && ![dict exists $o offset] } {
	    set limit_offset 0
	    set limit_count [dict get $o -limit-count]
	    set limit_field [dict get $o -limit-field]
	    set limit_progress 1
	  }

	  while { ![info exists result] || [info exists limit_progress] } {
	    set query [list]
	    dict for { k v } $o {
	      if { [string index $k 0] eq "-" } continue
	      lappend query $k $v
	    }
	    if { [info exists limit_offset] } {
	      lappend query "offset" $limit_offset "count" $limit_count
		    unset limit_progress
	    }
	    if { [catch [list ::http::geturl "https://api.vk.com/method/${func}" -query [::http::formatQuery {*}$query] -command [info coroutine]] errmsg] } {
	      {*}$error -1 $errmsg
	    } {
		    set token [yield]
		    if { [::http::status $token] eq "error" } {
		      {*}$error -2 "status: [::http::status $token], error: [::http::error $token]"
		    } elseif { [::http::status $token] ne "ok" } {
		      {*}$error -2 "status: [::http::status $token]"
		    } elseif { [::http::ncode $token] ne "200" } {
		      {*}$error -2 "server return code: [::http::code $token]"
		    } {
		    	set resp [::json::json2dict [encoding convertfrom utf-8 [::http::data $token]]]
		      if { [info exists limit_offset] } {
		        if { ![dict exists $resp response] } {
		          {*}$error -3 "no 'response' field in server response"
		        } elseif { ![dict exists $resp response count] } {
		          {*}$error -3 "no 'count' field in server response"
		        } elseif { ![dict exists $resp response $limit_field] } {
		          {*}$error -3 "no '$limit_field' field in server response"
		        } {
		          if { [info exists result] } {
		            dict set result $limit_field [concat [dict get $result $limit_field] [dict get $resp response $limit_field]]
		          } {
		            set result [dict get $resp response]
		          }
		        }
		        if { [llength [dict get $resp response $limit_field]] == $limit_count } {
		          incr limit_offset $limit_count
		          set limit_progress 1
		        }
		      } {
				    if { [dict exists $resp response] } {
				      set result [dict get $resp response]
			  	  } {
			  	    set result $resp
			  	  }
			  	}
			  	unset resp
		    }
		    ::http::cleanup $token
		  }
		}

    after 0 [linsert [dict get $o -callback] end $result]
    return
  }

}


package provide vkapi 1.0
