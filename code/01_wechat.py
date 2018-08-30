# !/usr/bin/python
# -*- encoding: utf-8 -*-
# @author:spider1998
import tornado.web
import tornado.options
import tornado.httpserver
import tornado.ioloop
import hashlib
import xmltodict
import time
import urllib
import json
import datetime
import tornado.gen
import os

from tornado.web import RequestHandler
from tornado.options import options,define
from tornado.httpclient import AsyncHTTPClient,HTTPRequest

import sys
reload(sys)
sys.setdefaultencoding('utf-8')

WECHAT_TOKEN = "itcast"
WECHAT_APP_ID="wx64fbd659ad83771d"
WECHAT_APP_SECRET="8c285778c1520ba1213959653c0a2735"
define("port",default=8000,type=int,help="")


"""接口调用凭据"""
class AccessToken(object):
    _access_token = None
    _create_time = 0
    _expires_in = 0

    @classmethod
    @tornado.gen.coroutine
    def update_access_token(cls):
        client = AsyncHTTPClient()
        url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&" \
              "appid=%s&secret=%s" %(WECHAT_APP_ID,WECHAT_APP_SECRET)
        resp = yield client.fetch(url)
        dict_data = json.loads(resp.body)
        if "errcode" in dict_data:
            raise Exception("wechat server error")
        else:
            cls._access_token = dict_data["access_token"]
            cls._expires_in = dict_data["expires_in"]
            cls._create_time = time.time()

    @classmethod
    @tornado.gen.coroutine
    def get_acess_token(cls):
        if time.time() - cls._create_time > (cls._expires_in - 200):
            #向服务器请求access_token
            yield cls.update_access_token()
            raise tornado.gen.Return(cls._access_token)
            pass
        else:
            raise tornado.gen.Return(cls._access_token)



class WechatHandler(RequestHandler):
    """对接微信服务器"""
    def prepare(self):
        signature = self.get_argument("signature")
        timestamp = self.get_argument("timestamp")
        nonce = self.get_argument("nonce")
        tmp = [WECHAT_TOKEN, timestamp, nonce]
        tmp.sort()
        tmp = "".join(tmp)
        real_signature = hashlib.sha1(tmp).hexdigest()
        if signature != real_signature:
            self.send_error(403)

    def get(self):
        echostr = self.get_argument("echostr")
        self.write(echostr)

    """对接图灵机器人"""
    def tuling(self,content):
        key = '5d4a2faaa0d3450ca8bcc2afe10f0196'
        api = 'http://www.tuling123.com/openapi/api?key=' + key + '&info='
        request = api + str(content)
        page = urllib.urlopen(request)
        response = page.read()
        dic_json = json.loads(response)
        return dic_json['text']

    def post(self):
        xml_data = self.request.body
        dict_data = xmltodict.parse(xml_data)
        msg_type = dict_data["xml"]["MsgType"]
        if msg_type == "text":
            text = dict_data["xml"]["Content"]
            content = self.tuling(text)
            resp_data = {
                "xml":{
                    "ToUserName":dict_data["xml"]["FromUserName"],
                    "FromUserName":dict_data["xml"]["ToUserName"],
                    "CreateTime":int(time.time()),
                    "MsgType":"text",
                    "Content":content,
                }
            }
            self.write(xmltodict.unparse(resp_data))
        elif msg_type == "event":
            if dict_data["xml"]["Event"] == "subscribe":
                """用户关注"""
                resp_data = {
                    "xml": {
                        "ToUserName": dict_data["xml"]["FromUserName"],
                        "FromUserName": dict_data["xml"]["ToUserName"],
                        "CreateTime": int(time.time()),
                        "MsgType": "text",
                        "Content": "Welcome",
                    }
                }
                if "EventKey" in dict_data["xml"]:
                    event_key = dict_data["xml"]["EventKey"]
                    scene_id = event_key[8:]
                    resp_data["xml"]["Content"] = u"Welcom%s" % scene_id
                self.write(xmltodict.unparse(resp_data))
            elif dict_data["xml"]["Event"] == "SCAN":
                scene_id = dict_data["xml"]["EventKey"]
                resp_data = {
                    "xml": {
                        "ToUserName": dict_data["xml"]["FromUserName"],
                        "FromUserName": dict_data["xml"]["ToUserName"],
                        "CreateTime": int(time.time()),
                        "MsgType": "text",
                        "Content": "your scan is %s num" % scene_id,
                    }
                }
                self.write(xmltodict.unparse(resp_data))
        elif msg_type == "voice":
            text = dict_data["xml"]["Recognition"]
            time.sleep(1)
            content = self.tuling(text)
            resp_data = {
                "xml": {
                    "ToUserName": dict_data["xml"]["FromUserName"],
                    "FromUserName": dict_data["xml"]["ToUserName"],
                    "CreateTime": int(time.time()),
                    "MsgType": "text",
                    "Content": content,
                }
            }
            self.write(xmltodict.unparse(resp_data))
        else:
            resp_data = {
                "xml": {
                    "ToUserName": dict_data["xml"]["FromUserName"],
                    "FromUserName": dict_data["xml"]["ToUserName"],
                    "CreateTime": int(time.time()),
                    "MsgType": "text",
                    "Content": "I Love you",
                }
            }
            self.write(xmltodict.unparse(resp_data))


class QrcodeHandler(RequestHandler):
    """微信服务器生成带参数的二维码"""
    @tornado.gen.coroutine
    def get(self):
        scene_id = self.get_argument("sid")
        try:
            access_token = yield AccessToken.get_acess_token()
        except Exception as e:
            self.write("errmsg: %s" % e)
        else:
            client = AsyncHTTPClient()
            url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=%s" % access_token
            req_data = {"action_name": "QR_LIMIT_SCENE", "action_info": {"scene": {"scene_id": scene_id}}}
            req = HTTPRequest(
                url=url,
                method="POST",
                body=json.dumps(req_data)
            )
            resp = yield client.fetch(req)
            dict_data = json.loads(resp.body)
            if "errcode" in dict_data:
                self.write("errmsg:get qrcode failed")
            else:
                ticket = dict_data["ticket"]
                qrcode_url = dict_data["url"]
                self.write('<img src="https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=%s"><br/>' % ticket)
                self.write('<p>%s</p>' % qrcode_url)

class ProfileHandler(RequestHandler):
    @tornado.gen.coroutine
    def get(self):
        code = self.get_argument("code")
        client = AsyncHTTPClient()
        url = "https://api.weixin.qq.com/sns/oauth2/access_token?" \
              "appid=%s&secret=%s&code=%s&grant_type=authorization_code" %(WECHAT_APP_ID,WECHAT_APP_SECRET,code)
        resp = yield client.fetch(url)
        dict_data = json.loads(resp.body)
        if "errcode" in dict_data:
            self.write("error occur")
        else:
            access_token = dict_data["access_token"]
            open_id = dict_data["openid"]
            url = "https://api.weixin.qq.com/sns/userinfo?access_token=%s" \
                  "&openid=%s&lang=zh_CN" %(access_token,open_id)
            resp = yield client.fetch(url)
            user_data = json.loads(resp.body)
            if "errcode" in user_data:
                self.write("error occur agin")
            else:
                self.render("index.html",user = user_data)

    """
    用户最终url
    https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx64fbd659ad83771d&redirect_uri=http%3A//www.spider1998.top/wechat8000/profile&response_type=code&scope=snsapi_userinfo&state=2#wechat_redirect
    
    http%3A//www.spider1998.top/wechat8000/profile
    """
class IndexHandler(RequestHandler):
    def get(self):
        self.write("aaaaa")


def main():
    tornado.options.parse_command_line()
    app=tornado.web.Application(
        [
            (r"/", IndexHandler),
            (r"/wechat8000",WechatHandler),
            (r"/qrcode",QrcodeHandler),
            (r"/wechat8000/profile", ProfileHandler),
        ],
        template_path=os.path.join(os.path.dirname(__file__),"template")
    )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()

