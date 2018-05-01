
function show_password(password){
  document.getElementById("password_box").innerHTML = password;

setTimeout(function(){
    document.getElementById("password_box").innerHTML = '';
}, 30000);
}
