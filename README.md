
This program is a Man in the middle

It will reroute all traffic on the network through the localhost and saves all data




process communication protocol:

  server to main:
  
    send action:
      add user = 1, delete user = 2, add url = 3, delete url = 4, get users = 5, get urls = 6, update password = 7

    if action is add user
      send [name, password, privilege]

    if action is delete user
      send user id

    if action is add url
      send [url,user id]

    if action is delete url
      send url id

    if action is update password
      send [user id, password]



  main to server:
  
    receive action

    if action is between 1 and 4
      update database and return successful or error code
      return codes:
        successful: 0
        already exists: 1
        invalid data: 2


    if action is get users
      return [(name,user id)]

    if action is get urls
      return [(url,url id)]



  main to MITM:
  
    push action:
      add user = 1, delete user = 2, add url = 3, delete url = 4

    if action is add user
      send [user id, ip address, privilege, [url]]

    if action is delete user
      send user id

    if action is add url
      send [user id,url]

    if action is delete url
      send [user id, url id]




* [] list
* () tuple
* {:} dictionary
