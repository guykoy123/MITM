
from flask import Flask,render_template,request,redirect,url_for
from random import randint

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
    users=get_users_list()
    return render_template('users_menu.html',users=users)

@app.route('/user_page/<name>/<key>')
def user_page(name,key):
    """
    show the user profile
    privilege, sites and account info can be seen here (maybe later statistics as well)
    """
    user = (name,key)
    print user
    privilege=get_user_privilege(user[1])
    print privilege
    return render_template('user_page.html',user=user,privilege=privilege)


#TODO:  add main function to start the site and setup communication to main program
if __name__ == '__main__':
    app.run(debug = True)
