
from flask import Flask,render_template,request,redirect,url_for,session
from random import randint
from multiprocessing import Pipe
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
        return render_template('users_menu.html',users=users)
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

        if request.method == 'POST':
            try:
                print request.form['url']
                main_conn.send(3)
                main_conn.send([request.form['url'],key])
            except Exception:
                main_conn.send(10)
                if request.form['privilege'] == 'blacklist':
                    main_conn.send([key,1])
                else:
                    main_conn.send([key,2])

        main_conn.send(7)
        main_conn.send(key)
        url_list=main_conn.recv()
        main_conn.send(key)
        violations=main_conn.recv()
        
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



@app.route('/show_password/<password>')
def show_password(password):
    """
    shows password for 30 seconds then returns to the previous page
    """
    if 'admin' in session:
        return render_template('show_password.html',password=password)
    return redirect(url_for('login'))




@app.route('/new_user',methods=['GET','POST'])
@app.route('/new_user/<message>',methods=['GET','POST'])
def new_user(message=""):
    """
    form for creating new user
    """
    if 'admin' in session:
        if request.method=="POST":

            if request.form['privilege'] == 'blacklist': #determine privilege selected
                privilege=1
            else:
                privilege=2

            main_conn.send(1)
            main_conn.send([request.form["name"],request.form["password"],privilege])
            code=main_conn.recv()

            if code ==1:
                message="User already exists!"
                return render_template('new_user.html',message=message)
            else:
                return redirect(url_for('users'))

        return render_template('new_user.html',message=message)
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
        print new_admin
        return render_template('admin_settings.html',user=new_admin)
    return redirect(url_for('login'))

@app.route('/user_login',methods=['GET','POST'])
@app.route('/user_login/<int:user_id>',methods=['GET','POST'])
@app.route('/user_login/<int:user_id>/<message>',methods=['GET','POST'])
def user_login(user_id=0,message=''):
    """
    displays the user login page
    if user logged on, sends users id and ip address to MITM
    """

    if request.method=='POST':
        username=request.form['name']
        password=request.form['password']
        main_conn.send(11)
        admin=main_conn.recv()

        if username==admin[1] and password==admin[2]:
            main_conn.send(13)
            main_conn.send([admin[0],request.form.get('ip_address')])
            session[str(admin[0])]=True
            return '''You are logged in'''

        else:
            main_conn.send(5)
            user_list=main_conn.recv()
            wrong_login=True
            for user in user_list:

                if user[0] == username:
                    main_conn.send(6)
                    main_conn.send(user[1])
                    check_user=main_conn.recv()

                    if check_user[1]==password:
                        wrong_login=False
                        main_conn.send(13)
                        main_conn.send([user[1],request.form.get('ip_address'),check_user[2]])
                        session[str(user[1])]=True
                        return '''You are logged in'''

            if wrong_login:
                message='Wrong username or password'
                return render_template('login_user.html',user_id=user_id, message=message)

    if str(user_id) not in session:
        user_id=0
    return render_template('login_user.html',user_id=user_id, message=message)


@app.route('/user_logout/<int:user_id>')
def user_logout(user_id):
    session.pop(str(user_id),None)
    return '''Bye'''


def main(conn=None):
    global main_conn #declare Pipe connection as global
    main_conn=conn
    app.config['network.monitor']='server:80'
    app.run(host='0.0.0.0',port=80)

if __name__ == '__main__':
    main()
