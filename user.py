
class User:
	
	def __init__(self,user_id,mac_address,privilege,url_list):
		self.user_id= user_id
		self.privilege=privilege
		self.mac_address=mac_address
		self.url_list=url_list

	def remove_url(self,url_id):
		for i in range(len(self.url_list)):
			if url_id==self.url_list[i][0]:
				del self.url_list[i]
				return 1
		return 0

	def add_url(self,url):
		self.url_list.append(url)

	def update_url_list(self,url_list):
		self.url_list=url_list

	def get_url_list(self):
		urls=list()
		for i in range(len(self.url_list)):
			urls.append(self.url_list[i][1])
		return urls

	def get_privilege(self):
		return self.privilege

	def set_privilege(self,p):
		self.privilege=p
		
	def get_mac(self):
		return self.mac_address

	def get_id(self):
		return self.user_id
