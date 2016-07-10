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

  variable setup

  variable rid
  variable response

  variable error

  constructor { args } {
    set setup [dict create lang 0 scope "friends,photos,audio,video,wall,groups,messages,offline"]

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
    {-scope        string -nodefault}
    {-lang         string -nodefault -restrict {ru ua be en es fi de it 0 1 2 3 4 5 6 7}}
    {-access_token string -nodefault}
    {-cookies      dict   -nodefault}
  }}} {
    ::procarg::parse
    if { ![array size opts] } {
      return $setup
    }
    if { [info exists opts(-app_id)] } {
      dict set setup app_id $opts(-app_id)
    }
    if { [info exists opts(-lang)] } {
	    dict set setup lang $opts(-lang)
    }
    if { [info exists opts(-access_token)] } {
      dict set setup access_token $opts(-access_token)
    }
    if { [info exists opts(-cookies)] } {
      dict set setup cookies $opts(-cookies)
    }
  }

  method auth { { args {
    {-login    string -allowempty false}
    {-password string -allowempty false}
    {-callback string -nodefault}
  }}} {
    ::procarg::parse
    coroutine [self object]::[set myrid [incr rid]] my Auth [array get opts] $myrid
    if { ![info exists opts(-callback)] } {
      vwait [self namespace]::response($myrid)
      set result $response($myrid)
      unset response($myrid)
      return $result
    }
    return
  }

  method Cookies { action {token {}} } {
    if { $action eq "format" } {
		  set result [list]
		  if { [dict exists $setup cookies] } {
		    dict for { key val } [dict get $setup cookies] {
		      lappend result "${key}=${val}"
		    }
		  }
		  if { [llength $result] } {
        return [list "Cookie" [join $result "; "]]
		  } {
		    return ""
		  }
    } elseif { $action eq "parse" } {
			foreach { key val } [::http::meta $token] {
				if { $key ne "Set-Cookie" } continue
				set val [split [lindex [split $val "\;"] 0] =]
				set key [string trim [lindex $val 0]]
				set val [string trim [join [lrange $val 1 end] =]]
				if { $val eq "DELETED" } {
				  if { [dict exists $setup cookies $key] } {
				    dict unset setup cookies $key
				  }
				} {
			  	dict set setup cookies $key $val
			  }
		  }
		} {
		  return -code error "::vkapi::Cookies error, unknown action."
		}
  }

  method Auth { o myrid } {
	  if { ![dict exists $o -callback] } {
	    dict set o -callback [list set [self namespace]::response($myrid)]
	  }
	  dict unset setup cookies
#	  puts "get cookies"
	  if { [catch [list ::http::geturl "https://new.vk.com/" -command [info coroutine]] errmsg] } {
	    {*}$error -100 "error while get cookies - $errmsg"
	  } {
	    set token [yield]
	    if { [::http::status $token] eq "error" } {
	      {*}$error -100 "error while get cookies - status: [::http::status $token], error: [::http::error $token]"
	    } elseif { [::http::status $token] ne "ok" } {
	      {*}$error -100 "error while get cookies - status: [::http::status $token]"
	    } elseif { [::http::ncode $token] ne "200" } {
	      {*}$error -100 "error while get cookies - server return code: [::http::code $token]"
	    } {
	      my Cookies parse $token
	      set query [dict create act login email [dict get $o -login] pass [dict get $o -password]]
	      set data [::http::data $token]
	      foreach key {_origin ip_h lg_h} {
	        if { ![regexp -nocase "name=\"$key\"\\s+value=\"\(\[^\"\]+)\"" $data -> val] } continue
	        dict set query $key $val
	      }
	      unset data
	      if { ![dict exists $setup cookies remixlang] } {
	        {*}$error -100 "error while get cookies - cookie 'remixlang' not found in server response"
	      } elseif { ![dict exists $setup cookies remixlhk] } {
	        {*}$error -100 "error while get cookies - cookie 'remixlhk' not found in server response"
	      } elseif { ![dict exists $query _origin] } {
	        {*}$error -100 "error while get cookies - form field '_origin' not found in server response"
	      } elseif { ![dict exists $query ip_h] } {
	        {*}$error -100 "error while get cookies - form field 'ip_h' not found in server response"
	      } elseif { ![dict exists $query lg_h] } {
	        {*}$error -100 "error while get cookies - form field 'lg_h' not found in server response"
	      }
	    }
	    ::http::cleanup $token
	    if { ![info exists result] } {
#		    puts "auth..."
	      if { [catch [list ::http::geturl "https://login.vk.com/" -command [info coroutine] -query [::http::formatQuery {*}$query] -headers [my Cookies format]] errmsg] } {
			    {*}$error -101 "error while auth - $errmsg"
	      } {
			    set token [yield]
	  		  if { [::http::status $token] eq "error" } {
			      {*}$error -101 "error while auth - status: [::http::status $token], error: [::http::error $token]"
			    } elseif { [::http::status $token] ne "ok" } {
			      {*}$error -101 "error while auth - status: [::http::status $token]"
			    } elseif { [::http::ncode $token] ne "302" } {
			      {*}$error -101 "error while auth - server return code: [::http::code $token]"
			    } elseif { ![dict exists [::http::meta $token] Location] } {
			      {*}$error -101 "error while auth - no location header in server response."
			    } {
			      my Cookies parse $token
			      if { ![dict exists $setup cookies p] } {
			        {*}$error -101 "error while auth - cookie 'p' not found in server response"
			      } elseif { ![dict exists $setup cookies l] } {
			        {*}$error -101 "error while auth - cookie 'l' not found in server response"
			      } elseif { [string first {__q_hash} [set location [dict get [::http::meta $token] Location]]] == -1 } {
			        {*}$error -101 "error while auth - no '__q_hash' string in location header of server response."
			      }
			    }
			    ::http::cleanup $token
			    if { ![info exists result] } {
#			      puts "auth2..."
			      if { [catch [list ::http::geturl $location -command [info coroutine] -headers [my Cookies format]] errmsg] } {
			      	{*}$error -102 "error while auth2 - $errmsg"
			      } {
			        set token [yield]
	  		  		if { [::http::status $token] eq "error" } {
					      {*}$error -102 "error while auth2 - status: [::http::status $token], error: [::http::error $token]"
					    } elseif { [::http::status $token] ne "ok" } {
					      {*}$error -102 "error while auth2 - status: [::http::status $token]"
					    } elseif { [::http::ncode $token] ne "302" } {
			  		    {*}$error -102 "error while auth2 - server return code: [::http::code $token]"
			  		  } {
			  		    my Cookies parse $token
					      if { ![dict exists $setup cookies remixsid] && ![dict exists $setup cookies remixsid6] } {
					        {*}$error -102 "error while auth2 - cookie 'remixsid' not found in server response"
			  		    }
			  		  }
			  		  ::http::cleanup $token
			  		  if { ![info exists result] } {
#			  		    puts "get access_token..."
			  		    if { [catch [list ::http::geturl "http://oauth.vk.com/authorize" -command [info coroutine] -headers [my Cookies format] -query [::http::formatQuery \
			  		      client_id     [dict get $setup app_id] \
			  		      scope         [dict get $setup scope] \
			  		      redirect_uri  "http://api.vk.com/blank.html" \
			  		      response_type "token" \
			  		      display       "wap"]] errmsg] \
			  		    } {
					      	{*}$error -103 "error while request access_token - $errmsg"
			  		    } {
			  		      set token [yield]
			  		  		if { [::http::status $token] eq "error" } {
							      {*}$error -103 "error while request access_token - status: [::http::status $token], error: [::http::error $token]"
							    } elseif { [::http::status $token] ne "ok" } {
							      {*}$error -103 "error while request access_token - status: [::http::status $token]"
							    }
							    if { [::http::ncode $token] eq "302" } {
							      if { ![dict exists [::http::meta $token] Location] } {
							        {*}$error -103 "error while request access_token - no location header in server 302 response."
							      } elseif { [string first {grant_access} [set location [dict get [::http::meta $token] Location]]] == -1 } {
							        {*}$error -103 "error while request access_token - invalid location header in server 302 response"
							      }
							    } elseif { [::http::ncode $token] eq "200" } {
										if { ![regexp -nocase "action=\"(https://login.vk.com/\\?act=grant_access\[^\"\]+)\"" [::http::data $token] -> location] } {
					  		    	{*}$error -103 "error while request access_token - no grant access link in server response."
						  		  }
							    } {
					  		    {*}$error -103 "error while request access_token - server return code: [::http::code $token]"
							    }
					  		  ::http::cleanup $token
					  		  if { ![info exists result] } {
#					  		    puts "get access_token2..."
					  		    if { [catch [list ::http::geturl $location -command [info coroutine] -headers [my Cookies format] -query ""] errmsg] } {
					  		      {*}$error -104 "error while request2 access_token - $errmsg"
					  		    } {
					  		      set token [yield]
					  		  		if { [::http::status $token] eq "error" } {
									      {*}$error -104 "error while request2 access_token - status: [::http::status $token], error: [::http::error $token]"
									    } elseif { [::http::status $token] ne "ok" } {
									      {*}$error -104 "error while request2 access_token - status: [::http::status $token]"
							  		  } elseif { [::http::ncode $token] ne "302" } {
							  		    {*}$error -104 "error while request2 access_token - server return code: [::http::code $token]"
							  		  } elseif { ![dict exists [::http::meta $token] Location] } {
			    						  {*}$error -104 "error while request2 access_token - no location header in server response."
									    } elseif { ![regexp {#access_token=([^&]+)&} [dict get [::http::meta $token] Location] -> access_token] } {
									      {*}$error -104 "error while request2 access_token - no access_token in location header of server response."
									    }
									    ::http::cleanup $token
									    if { ![info exists result] } {
									      my setup -access_token $access_token
									      set result "status ok"
									    }
					  		    }
					  		  }
			  		    }
			  		  }
			      }
			    }
	      }
	    }
	  }
    after 0 [linsert [dict get $o -callback] end $result]
    return
  }

  method Request { func o myrid } {
	  if { ![dict exists $o -callback] } {
	    dict set o -callback [list set [self namespace]::response($myrid)]
	  }
	  if { ![dict exists $o lang] } {
		  dict set o lang [dict get $setup lang]
		}
		if { [dict exists $setup access_token] } {
		  dict set o access_token [dict get $setup access_token]
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
	    puts "request: https://api.vk.com/method/${func}"
	    puts "query: [::http::formatQuery {*}$query]"
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
