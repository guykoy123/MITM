
from flask import Flask,render_template,request,redirect,url_for,session
from random import randint
from multiprocessing import Pipe

app = Flask(__name__)
app.secret_key="shit.py"
no_login ="Please login first."

@app.route('/', methods=['GET','POST'])
@app.route('/<message>', methods=['GET','POST'])
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
                    return render_template('login_page.html',message=message)
            else:
                message="username or password is incorrect"
                return render_template('login_page.html',message=message)

        return render_template('login_page.html',message=message)

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

        return render_template('user_page.html',user=user,url_list=url_list,user_id=key)
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
    if 'admin' in session:
        if request.method=='POST':
            username=request.form['username']
            password=request.form['password']
            print username,password

        main_conn.send(11)
        return render_template('admin_settings.html',user=main_conn.recv())
    return redirect(url_for('login'))



def main(conn=None):
    global main_conn #declare Pipe connection as global
    main_conn=conn
    app.run(debug=True)

if __name__ == '__main__':
    main()
