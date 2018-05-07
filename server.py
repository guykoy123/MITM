
from flask import Flask,render_template,request,redirect,url_for
from random import randint
from multiprocessing import Pipe

app = Flask(__name__)


@app.route('/')
def login():
    """
    display login page before giving access to the settings
    """
    #TODO: add login page
    return redirect(url_for('main_menu'))


@app.route('/main_menu')
def main_menu():
    """
    shows main menu where all the different functions can be viewed
    """
    return render_template('main_menu.html')


@app.route('/users')
def users():
    """
    show a list to all users with a link to each users profile
    """
    main_conn.send(5)
    users=main_conn.recv()
    print users
    return render_template('users_menu.html',users=users)


@app.route('/user_page/<key>', methods=['GET', 'POST'])
def user_page(key):
    """
    show the user profile
    privilege, sites and account info can be seen here (maybe later statistics as well)
    """
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


@app.route('/remove_url/<url_id>/<user_id>')
def remove_url(url_id,user_id):
    """
    deletes the url from the database
    then redirects back to the user page
    """
    main_conn.send(4)
    main_conn.send(url_id)
    print user_id
    return redirect(url_for('user_page',key=user_id))


@app.route('/show_password/<password>')
def show_password(password):
    """
    shows password for 30 seconds then returns to the previous page
    """
    return render_template('show_password.html',password=password)


@app.route('/new_user',methods=['GET','POST'])
@app.route('/new_user/<message>',methods=['GET','POST'])
def new_user(message=""):
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
            print "redirecting to users menu"
            return redirect(url_for('users'))
    return render_template('new_user.html',message=message)

def main(conn=None):
    global main_conn #declare Pipe connection as global
    main_conn=conn
    app.run(debug=True)

if __name__ == '__main__':
    main()
