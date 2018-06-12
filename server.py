
from flask import Flask,render_template,request,redirect,url_for,session
from random import randint
from multiprocessing import Pipe
import logging
#from forms import *

app = Flask(__name__)
app.secret_key="shit.py"
no_login ="Please login first."

@app.route('/', methods=['GET','POST'])
@app.route('/login', methods=['GET','POST'])
@app.route('/login/<message>', methods=['GET','POST'])
def login(message=''):
    """
    display login page before giving access to the settings
    """
    if 'admin' not in session:
        if request.method=='POST':
            name=request.form['name']
            password=request.form['password']
            main_conn.send(11)
            admin=main_conn.recv()
            if admin[1] == name:
                if admin[2] == password:
                    session['admin']=True
                    return redirect(url_for('main_menu'))
                else:
                    message="username or password is incorrect"
                    return render_template('login_admin.html',message=message)
            else:
                message="username or password is incorrect"
                return render_template('login_admin.html',message=message)

        return render_template('login_admin.html',message=message)

    return redirect(url_for('main_menu'))



@app.route('/main_menu')
def main_menu():
    """
    shows main menu where all the different functions can be viewed
    """
    if 'admin' in session:
        return render_template('main_menu.html')
    return redirect(url_for('login'))


@app.route('/users')
def users():
    """
    show a list to all users with a link to each users profile
    """
    if 'admin' in session:
        main_conn.send(5)
        users=main_conn.recv()
        new_hosts=main_conn.recv()
        return render_template('users_menu.html',users=users,new_hosts=new_hosts)
    return redirect(url_for('login'))



@app.route('/user_page/<key>', methods=['GET', 'POST'])
def user_page(key):
    """
    show the user profile
    privilege, sites and account info can be seen here (maybe later statistics as well)
    """
    if 'admin' in session:
        main_conn.send(6)
        main_conn.send(key)
        user=main_conn.recv()
        print user
        if request.method == 'POST':
            try:
                print request.form['url']
                main_conn.send(3)
                main_conn.send([request.form['url'].split('www.')[-1],key])
            except Exception:
                main_conn.send(10)
                if request.form['privilege'] == 'blacklist':
                    main_conn.send([key,1])
                else:
                    main_conn.send([key,2])

        main_conn.send(7)
        main_conn.send(key)
        url_list=main_conn.recv()
        print url_list
        main_conn.send(13)
        main_conn.send(key)
        violations=main_conn.recv()
        print violations

        return render_template('user_page.html',user=user,url_list=url_list,user_id=key,violations=violations)
    return redirect(url_for('login'))


@app.route('/remove_url/<url_id>/<user_id>')
def remove_url(url_id,user_id):
    """
    deletes the url from the database
    then redirects back to the user page
    """
    if 'admin' in session:
        main_conn.send(4)
        main_conn.send(url_id)
        return redirect(url_for('user_page',key=user_id))
    return redirect(url_for('login'))




@app.route('/logout')
def logout():
    session.pop('admin',None)
    return redirect(url_for('login'))


@app.route('/admin_settings',methods=['GET','POST'])
def admin_settings():
    """
    shows admin settings
    allows to change login details
    """
    if 'admin' in session:
        if request.method=='POST':
            username=request.form['username']
            password=request.form['password']
            print username,password
            main_conn.send(11)
            old_admin=main_conn.recv()
            print old_admin
            if username != old_admin[1]:
                main_conn.send(12)
                main_conn.send([old_admin[0],username])

            if password != old_admin[2]:
                main_conn.send(8)
                print 'shit'
                main_conn.send([old_admin[0],password])
        main_conn.send(11)
        new_admin=main_conn.recv()
        main_conn.send(15)
        ignored = main_conn.recv()
        return render_template('admin_settings.html',user=new_admin,ignored=ignored)
    return redirect(url_for('login'))

@app.route('/add_user/<key>')
def add_user(key):
    main_conn.send(14)
    main_conn.send((key,2)) #set ignore value to 2 (do not ignore)
    main_conn.send(10)
    main_conn.send((key,1)) #set default privilege to 1 (blacklist)
    return redirect(url_for('users'))

@app.route('/ignore_host/<key>')
def ignore_host(key):
    main_conn.send(14)
    main_conn.send((key,1)) #set ignore value to 1 (ignore)
    return redirect(url_for('users'))

def main(conn=None):
	#setup logging to file logFile.log
    logging.basicConfig(filename='server_log.log',level=logging.DEBUG, format='%(lineno)s - %(levelname)s : %(message)s')
    global main_conn #declare Pipe connection as global
    main_conn=conn
    #app.config['network.monitor']='server:80'
    app.run(host='127.0.0.1',port=5000,debug=True)

if __name__ == '__main__':
    main()
