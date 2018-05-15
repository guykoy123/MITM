
class User:

    def __init__(self,user_id,ip_address,privilege,url_list):
        self.user_id= user_id
        self.privilege=privilege
        self.ip_address=ip_address
        self.url_list=url_list

    def remove_url(self,url_id):
        for i in range(len(self.url_list)):
            if url_id==self.url_list[i][0]:
                del self.url_list[i]

    def add_url(self,url):
        self.url_list.append(url)

    def get_url_list(self):
        urls=list()
        for i in range(len(self.url_list)):
            urls.append(self.url_list[i][1])
        return urls

    def get_privilege(self):
        return self.privilege

    def get_ip(self):
        return self.ip_address

    def get_id(self):
        return self.user_id
