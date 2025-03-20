#!/usr/bin/env python3
import json
import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from a2wsgi import ASGIMiddleware
from sqlmodel import SQLModel, Field, create_engine, Session, select
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware


dburl = "postgresql://{{ psql_user }}:{{ psql_pass }}@169.254.100.3/firewalldb"
engine = create_engine(dburl)
webapp = FastAPI(debug=True)
webapp.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins, adjust for security as needed
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
)


class interfaces(SQLModel,table=True):
    __table_args__ = {'extend_existing': True}
    id: int | None = Field(default=None, primary_key=True)
    interface: str = Field(unique=True)
    int_type: str | None
    parent: str | None = None
    ip: str = Field(unique=True)
    gateway: str | None = None
    is_provider: bool | None = Field(default=False)
    priority: int | None
    is_dhcp: bool | None = Field(default=False)
    dhcp_start: str | None = None
    dhcp_end:  str | None = None
    int_delete: bool | None = Field(default=False)
    int_update: bool | None = Field(default=False)



class firewall_rules(SQLModel, table= True):
    __table_args__ = {'extend_existing': True}
    id: int | None = Field(default=None, primary_key=True)
    fworder: int
    action: str
    protocol: str
    src_interface: str | None = Field(foreign_key="interfaces.interface")
    dst_interface: str | None = Field(foreign_key="interfaces.interface")
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: str | None = None
    dst_port: str | None = None

class static_routes(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    network: str
    gateway: str
    gateway_int: str | None = Field(foreign_key="interfaces.interface")
    masquerade: bool | None = Field(default=False)


SQLModel.metadata.create_all(engine)

def firewall_config(raction):
    uri="http://169.254.100.2:5000/rules"
    headers = {"Content-type": "Application/json"}
    values = {"action":raction}
    api_call = requests.post(uri, headers=headers, json=values)
    return api_call.content

def get_fw_data(table, uid):
    session = Session(engine)
    try:
        fwdata = session.exec(select(table).where(table.id == uid)).one()
        return fwdata, session
    except:
        fwdata = 'not_found'
        return fwdata, session
@webapp.get('/fw/rules')
def retrieve_firewall_rules():
    with Session(engine) as session:
        fw_rules = session.exec(select(firewall_rules).order_by(firewall_rules.fworder,firewall_rules.id)).all()
        msg = [rule.model_dump() for rule in fw_rules]
        return JSONResponse(content=msg, status_code=200)

@webapp.post('/fw/rules',status_code=200)
def insert_firewall_rule(fwrule: firewall_rules):
    try:
        with Session(engine) as session:
            session.add(fwrule)
            session.commit()
            session.refresh(fwrule)
        msg = firewall_config(raction="gen_rules").decode('utf8')
        if "Error" in msg:
            session.delete(fwrule)
            session.commit()
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.put('/fw/rules/{rid}', status_code=200)
def update_firewall_rule(rid, apival: firewall_rules):
    rcollumn = dict(apival)
    fallback_data=dict()
    print(rcollumn)
    try:
        fwdata, session = get_fw_data(firewall_rules, rid)
        if fwdata == 'not_found':
            msg = 'Could not retrieve data'
            raise Exception
        for rkey, rval in rcollumn.items():
            print(rkey,rval)
            #if rval or (rkey =='src_interface' or rkey =='dst_interface') : ##Fix for null src and dst interface, option ALL on wgui
            #Collect current attributes
            if rkey == 'id':
                continue
            fallback_data[rkey]=getattr(fwdata,rkey)
            setattr(fwdata, rkey, rval)
        print(fwdata)
        session.add(fwdata)
        session.commit()
        session.refresh(fwdata)
        msg = firewall_config(raction='gen_rules').decode('utf8')
        if 'Error' in str(msg):
            #Revert database data to previous working condition
            for rkey,rval in fallback_data.items():
                setattr(fwdata,rkey,rval)
            session.commit()
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.delete('/fw/rules/{rid}', status_code=200)
def delete_firewall_rule(rid):
    try:
        fwdata, session = get_fw_data(firewall_rules,rid)
        if fwdata == 'not_found':
            msg = 'Could not retrieve data'
            raise Exception
        session.delete(fwdata)
        session.commit()
        msg = firewall_config(raction='gen_rules').decode('utf8')
        if 'Error' in str(msg):
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.get('/fw/interfaces', status_code=200)
def retrieve_interfaces():
    with Session(engine) as session:
        rinterfaces = session.exec(select(interfaces).order_by(interfaces.id)).all()
        int_list = [rint.model_dump() for rint in rinterfaces]
        return JSONResponse(content=int_list,status_code=200)


@webapp.post('/fw/interfaces', status_code=200)
def insert_interface(vinterface: interfaces):
    try:
        with Session(engine) as session:
            session.add(vinterface)
            session.commit()
            session.refresh(vinterface)
        msg = firewall_config(raction="gen_int").decode('utf8')
        if 'Error' in msg:
            session.delete(vinterface)
            session.commit()
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.put('/fw/interfaces/{iid}', status_code=200)
def update_interfaces(iid, apival:interfaces):
    rcollumn = dict(apival)
    print(rcollumn)
    fallback_data = dict()
    try:
        fwdata,session = get_fw_data(interfaces, iid)
        if fwdata == 'not_found':
            msg = 'Could not retrieve data'
            raise Exception
        for ikey, ival in rcollumn.items():
            print(ikey, ival)
            if ikey=='id':
                continue
            #Collect current attributes
            fallback_data[ikey] = getattr(fwdata,ikey)
            #Update attributes
            setattr(fwdata, ikey, ival)
            setattr(fwdata,'int_update',True)
        print(fwdata)
        session.add(fwdata)
        session.commit()
        session.refresh(fwdata)
        msg = firewall_config(raction='update_int').decode('utf8')
        setattr(fwdata, 'int_update',False)
        session.add(fwdata)
        session.commit()
        session.refresh(fwdata)
        if 'Error' in msg:
            #Revert changes on interface in case an error appears
            for ikey, ival in fallback_data.items():
                setattr(fwdata, ikey, ival)
            setattr(fwdata, 'int_update', False)
            session.commit()
            session.refresh(fwdata)
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg": msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.delete('/fw/interfaces/{iid}', status_code=200)
def delete_interface(iid):
    try:
        fwdata,session = get_fw_data(interfaces, iid)
        if fwdata == 'not_found':
            msg = 'Could not retrieve data'
            raise Exception
        setattr(fwdata, 'int_delete', True)
        session.add(fwdata)
        session.commit()
        session.refresh(fwdata)
        msg = firewall_config(raction='delete_int').decode('utf8')
        if 'Error' in msg:
            setattr(fwdata, 'int_delete', False)
            session.add(fwdata)
            session.commit()
            session.refresh(fwdata)
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg": msg}, status_code=400)
    finally:
        if session:
            session.close()


@webapp.get('/fw/routes', status_code=200)
def retrieve_routes():
    with Session(engine) as session:
        routes = session.exec(select(static_routes).order_by(static_routes.id)).all()
        route_list=[route.model_dump() for route in routes]
        return JSONResponse(content=route_list,status_code=200)

@webapp.post('/fw/routes', status_code=200)
def insert_route(sroute: static_routes):
    try:
        with Session(engine) as session:
            session.add(sroute)
            session.commit()
            session.refresh(sroute)
        msg = firewall_config(raction="gen_rules").decode('utf8')
        if "Error" in msg:
            session.delete(sroute)
            session.commit()
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.put('/fw/routes/{rid}', status_code=200)
def update_route(rid, apival: static_routes):
    rcollumn = dict(apival)
    print(rcollumn)
    fallback_data=dict()
    try:
        fwdata, session = get_fw_data(static_routes, rid)
        if fwdata == 'not_found':
            msg = 'Could not retrieve data'
            raise Exception
        for rkey, rval in rcollumn.items():
            if rval is not None:
                #Collect current attributes
                fallback_data[rkey]=getattr(fwdata,rkey)
                setattr(fwdata, rkey, rval)
        print(fwdata)
        session.add(fwdata)
        session.commit()
        session.refresh(fwdata)
        msg = firewall_config(raction='gen_rules').decode('utf8')
        if 'Error' in str(msg):
            #Revert database data to previous working condition
            for rkey,rval in fallback_data.items():
                setattr(fwdata,rkey,rval)
            session.commit()
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()

@webapp.delete('/fw/routes/{rid}', status_code=200)
def delete_firewall_rule(rid):
    try:
        fwdata, session = get_fw_data(static_routes,rid)
        if fwdata == 'not_found':
            msg = 'Could not retrieve data'
            raise Exception
        session.delete(fwdata)
        session.commit()
        msg = firewall_config(raction='gen_rules').decode('utf8')
        if 'Error' in str(msg):
            raise Exception
        return JSONResponse(content={"msg":msg}, status_code=200)
    except:
        return JSONResponse(content={"msg":msg}, status_code=400)
    finally:
        if session:
            session.close()


application = ASGIMiddleware(webapp)
