function check_form(){
  var pass = document.forms["new_user_form"]["password"];
  var pass2 = document.forms["new_user_form"]["password2"];


  if (pass.value.length < 6)
  {
    window.alert("Password must be at least 6 characters long.");
    password.focus();

    return false;
  }

  if (pass.value != pass2.value)
  {
    window.alert("Passwords do no match.")
    password2.focus()
    return false;
  }
  return true

}
