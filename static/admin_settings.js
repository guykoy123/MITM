function check_form(){
  var pass = document.forms["settings_form"]["password"];

  if (pass.value.length < 8)
  {
    window.alert("Password must be at least 8 characters long.");
    password.focus();
    return false;
  }
}
