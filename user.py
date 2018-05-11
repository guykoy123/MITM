class User:
    def __init__(self,privilege,ip_address,url_list):
        self.privilege=privilege
        self.ip_address=ip_address
        self.url_list=url_list
        
    def remove_url(self,url_id):
        for i in range(len(self.url_list)):
            if url_id==self.url_list[i][0]:
                del self.url_list[i]
