import mechanize, random, cookielib

def getProxies():
	#This is what gets a random good proxy from rmccurdy's list
	browser = mechanize.Browser()
	browser.set_handle_robots(False)
	page = browser.open('http://rmccurdy.com/scripts/proxy/good.txt')

	proxies = []

	for proxy in page.readlines():
		proxies.append({'http': proxy.replace('\n', '')})
	
	#Returns it in mechanize's format
	return proxies

class anonBrowser(mechanize.Browser):

	def __init__(self, proxies = getProxies(), user_agents = []):
		mechanize.Browser.__init__(self)
		self.set_handle_robots(False)
		self.proxies = proxies
		self.user_agents = user_agents + ['Mozilla/4.0 ',\
		'FireFox/6.01','ExactSearch', 'Nokia7110/1.0']
		self.cookie_jar = cookielib.LWPCookieJar()
		self.set_cookiejar(self.cookie_jar)
		self.anonymize()

	def clear_cookies(self):
		self.cookie_jar = cookielib.LWPCookieJar()
		self.set_cookiejar(self.cookie_jar)

	def change_user_agent(self):
		self.addheaders = [('User-agent', random.choice(self.user_agents))]

	def change_proxy(self):
		if self.proxies:
			self.set_proxies(random.choice(self.proxies))

	def anonymize(self, sleep = False):
		self.clear_cookies()
		self.change_user_agent()
		self.change_proxy()

		if sleep:
			time.sleep(60)

ab = anonBrowser()

for attempt in range(1, 5):
	ab.anonymize()
	print '[*] Fetching page'
	response = ab.open('URL')
