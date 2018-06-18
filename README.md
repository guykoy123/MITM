
This program is a Man in the middle

It will reroute all traffic on the network through the localhost and saves all data

TODO:
  fix privilege updating
  url removing
  add email notification


privilege:

  0 - admin
  1 - blacklist
  2 - whitelist



process communication protocol:

  server to main:

    send action:
      add user : 1,
      delete user : 2,
      add url : 3,
      delete url : 4,
      get users list (without admin) : 5,
      get user : 6,
      get urls : 7,
      update password : 8,
      update ip : 9
      update privilege : 10
      get admin : 11
      update username : 12
      user connected : 13
      get violations : 14



    if action is add user
      send [name, password, privilege]

    if action is delete user
      send user id

    if action is add url
      send [url,user id]

    if action is delete url
      send url id

    if action is get user
      send user id

    if action is get urls
      send user id

    if action is update password
      send [user id, new password]

    if action is update ip
      send [user id, ip address]

    if action is update username
      send [user id, new username]

    if action is user connected
      send [user id,ip address]

    if action is get Violations
      send user id


  main to server:

    receive action

    if action is get user
      return [name,password,privilege]

    if action is get users
      return [(name,user id)]
      #does not return the admin user

    if action is get urls
      return [(url,url id)]

    if action is get admin
      return [user id,username,password]

    if action is get Violations
      return [time,url]






    send action:
      delete user : 2,
      add url : 3,
      delete url : 4


  main to MITM:
    if action is delete user
      send user id

    if action is add url
      send [user id,url]

    if action is delete url
      send [user id, url id]




* [] list
* () tuple
* {:} dictionary
