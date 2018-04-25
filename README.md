
This program is a Man in the middle

It will reroute all traffic on the network through the localhost and saves all data




process communication protocol:

  server to main:
    push action to queue: add user : 1, delete user : 2, add url : 3, delete url : 4, get users : 5, get urls : 6
    if action is add user,  send name, password and privilege
    if action is delete user, send user id
    if action is add url, send url,user id
    if action is delete url, send url id

  main to server:
    get action
    if action is between 1 and 4, update database
    if action is get users, return list of tuples (name,user id)
    if action is get urls, return list of tuples (url,url id)

  main to MITM:
    push action, add user : 1, delete user : 2, add url : 3, delete url : 4,
    if action is add user,  send user id, privilege, url:url id
    if action is delete user, send user id
    if action is add url, send url, user id
    if action is delete url, send user id, url id
