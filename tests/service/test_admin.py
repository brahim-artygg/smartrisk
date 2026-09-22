from __future__ import annotations

import http.client
import json
import threading

from smartrisk.service.admin import AdminService
from smartrisk.service.auth import AuthService, AuthStore
from smartrisk.service.developer_api import DeveloperStore
from smartrisk.service.http import serve
from smartrisk.service.service import ScanService
from smartrisk.service.store import JobStore


class FakeMailer:
    def __init__(self): self.verification_tokens=[]; self.reset_tokens=[]
    def send_verification(self,email,token): self.verification_tokens.append(token)
    def send_password_reset(self,email,token): self.reset_tokens.append(token)


class FakeReport:
    status='complete'
    def to_dict(self):
        return {'status':'complete','risk':{'score':10,'band':'low','confidence':1,'coverage':1},'verdict':{'code':'LOW_RISK'},'engines':[],'risk_dimensions':{}}


class FakeEngine:
    def analyze(self,request,run_id=None): return FakeReport()


def request(server,method,path,body=None,headers=None):
    host,port=server.server_address
    conn=http.client.HTTPConnection(host,port,timeout=5)
    hdr=dict(headers or {})
    payload=None
    if body is not None:
        payload=json.dumps(body); hdr['Content-Type']='application/json'
    conn.request(method,path,payload,hdr)
    resp=conn.getresponse(); raw=resp.read()
    data=json.loads(raw or b'{}') if resp.getheader('Content-Type','').startswith('application/json') else raw
    return resp,data


def login_admin(server, auth):
    auth.register('admin@example.com','correct horse battery staple')
    auth.verify_email(auth.mailer.verification_tokens[-1])
    user=auth.store.get_user_by_email('admin@example.com')[0]
    auth.store.set_user_role(user.id,'admin')
    resp,_=request(server,'POST','/v1/auth/login',{'email':'admin@example.com','password':'correct horse battery staple'})
    return resp.getheader('Set-Cookie').split(';',1)[0]


def test_admin_console_requires_role_and_csrf(tmp_path):
    scan=ScanService(JobStore(tmp_path/'db.sqlite3'),FakeEngine(),max_workers=1)
    auth=AuthService(AuthStore(tmp_path/'db.sqlite3'),FakeMailer())
    server=serve('127.0.0.1',0,service=scan,auth_service=auth)
    t=threading.Thread(target=server.serve_forever,daemon=True); t.start()
    try:
        response,_=request(server,'GET','/v1/admin/overview')
        assert response.status==401
        cookie=login_admin(server,auth)
        response,_=request(server,'GET','/admin',headers={'Cookie':cookie})
        assert response.status==200
        response,_=request(server,'GET','/v1/admin/overview',headers={'Cookie':cookie})
        assert response.status==200 and 'users' in _
        csrf=(request(server,'GET','/v1/admin/csrf',headers={'Cookie':cookie})[1])['csrf_token']
        response,data=request(server,'POST','/v1/admin/settings/ads_enabled',{'value':False},{'Cookie':cookie})
        assert response.status==403 and data['code']=='CSRF_INVALID'
        response,data=request(server,'POST','/v1/admin/settings/ads_enabled',{'value':False},{'Cookie':cookie,'X-CSRF-Token':csrf})
        assert response.status==200 and data['setting']['value']=='false'
    finally:
        server.shutdown();server.server_close();server.smartrisk_developer_api.shutdown();scan.executor.shutdown(wait=True)


def test_admin_plan_changes_persist_and_affect_api(tmp_path):
    path=tmp_path/'db.sqlite3'
    store=DeveloperStore(path)
    admin=AdminService(path)
    user=admin.store.auth.create_user('u@example.com','hash')
    updated=admin.store.update_plan('developer',{'monthly_scan_limit':777,'batch_limit':111,'price_usdt':17.5,'active':True},user.id)
    assert updated['monthly_scan_limit']==777 and updated['batch_limit']==111
    store2=DeveloperStore(path)
    p=store2.plan('developer')
    assert p['monthly_scan_limit']==777 and p['batch_limit']==111 and p['price_usdt']==17.5
    store2.ensure_development_subscription(user.id)
    _,raw=store2.create_key(user.id,'x')
    _,plan=store2.authenticate_key(raw)
    assert plan['monthly_scan_limit']==777 and plan['batch_limit']==111
    admin.store.update_plan('developer',{'active':False},user.id)
    try:
        store2.authenticate_key(raw)
        assert False,'inactive plan must reject API key'
    except Exception as exc:
        assert getattr(exc,'code',None)=='PLAN_INACTIVE'


def test_admin_can_disable_and_reenable_key_and_audit(tmp_path):
    path=tmp_path/'db.sqlite3'
    store=DeveloperStore(path); admin=AdminService(path)
    user=admin.store.auth.create_user('u@example.com','hash')
    store.ensure_development_subscription(user.id); meta,raw=store.create_key(user.id,'bot')
    admin.store.key_state(meta['id'],'disabled',user.id)
    try: store.authenticate_key(raw); assert False
    except Exception as exc: assert getattr(exc,'code',None)=='API_KEY_DISABLED'
    admin.store.key_state(meta['id'],'active',user.id)
    assert store.authenticate_key(raw)[0]['id']==meta['id']
    admin.store.update_plan('developer',{'price_usdt':25},user.id)
    coupon=admin.store.create_coupon({'code':'SAVE20','discount_type':'percent','discount_value':20},user.id)
    grant=admin.store.create_grant({'user_id':user.id,'plan_id':'developer','reason':'partner'},user.id)
    ad=admin.store.create_ad({'title':'Launch','body':'Welcome'},user.id)
    pay=admin.store.create_payment({'user_id':user.id,'amount_usdt':25,'plan_id':'developer'},user.id)
    audit=admin.store.audit_log(100,0)['data']
    ids={x['target_type'] for x in audit}
    assert {'plan','coupon','grant','ad','payment','api_key'}<=ids
    assert coupon['code']=='SAVE20' and grant['status']=='active' and ad['active'] is True and pay['status']=='pending'
