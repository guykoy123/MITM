
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

    return render_template('user_page.html',user=user,url_list=url_list)


def main(conn=None):
    global main_conn #declare Pipe connection as global
    main_conn=conn
    app.run(debug=True)

if __name__ == '__main__':
    main()
