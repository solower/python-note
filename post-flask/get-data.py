#!/usr/bin/env python
#-*- coding:utf-8 -*-
import re
import json
from flask import Flask, request,jsonify
from elasticsearch import Elasticsearch
from tldextract import extract  

app = Flask(__name__)

class Esearch(object):
    def __init__(self, elastic=None, url='http://es-server:9200/', index='whois-index', doctype=None, offset=0, limit=500):    
        self.elastic = elastic or Elasticsearch(url)
        self.index = index
        self.doctype = doctype
        self.offset = offset
        self.limit = limit

    def onelevel(self,subdomain):
        try:
            ext = extract(subdomain)
            domain=ext.domain + "." + ext.suffix
        except:
            pass
        return domain
    
    def search(self, filed=None, vlist=[]):
        result = []
        body = {
          "query": {
            "bool": {
              "should": []
            }
          },
          "from": self.offset,
          "size": self.limit,
        }

        if filed not in ['email','domain','phone','username']:
            print "无此关键字类型"
            return "TypeError"
            
        if filed == 'email':
            for v in vlist:
                vquery = [
                  {
                    "query_string": {
                      "default_field": "email",
                      "query": "\"%s\"" % str(v)
                    }
                  },
                  {
                    "query_string": {
                      "default_field": "email2",
                      "query": "\"%s\"" % str(v)
                    }
                  }
                ]
                body["query"]["bool"]["should"].append(vquery)
                
        if filed == 'phone':
            for v in vlist:
                vquery = [
                  {
                    "query_string": {
                      "default_field": "phone",
                      "query": "\"%s\"" % str(v)
                    }
                  },
                  {
                    "query_string": {
                      "default_field": "phone2",
                      "query": "\"%s\"" % str(v)
                    }
                  }
                ]
                body["query"]["bool"]["should"].append(vquery)
                
        if filed  == 'username':
            for v in vlist:
                vquery = {
                  "query_string": {
                    "default_field": "username",
                    "query": "\"%s\"" % str(v)
                  }
                }
                body["query"]["bool"]["should"].append(vquery)

        if filed  == 'domain':
            for v in vlist:
                domain = self.onelevel(v)
                vquery = {
                  "query_string": {
                    "default_field": "domain",
                    "query": "\"%s\"" % domain
                  }
                }
                body["query"]["bool"]["should"].append(vquery)
        if len(vlist) <50:
            response = self.elastic.search(index=self.index, doc_type=self.doctype, body=body, request_timeout=60)
        if 50 < len(vlist) < 100:
            response = self.elastic.search(index=self.index, doc_type=self.doctype, body=body, request_timeout=120)
        if 100 < len(vlist) < 200:
            response = self.elastic.search(index=self.index, doc_type=self.doctype, body=body, request_timeout=200)
        if len(vlist) > 200:
            print "一次性查询量超过最大限制（一次最多查询200条）"
            return "TotalError"
        
        for item in response['hits']['hits']:
            source = item['_source']
            source["databasename"] = item["_index"]
            if source not in result:
                result.append(source)
        
        return result
    
@app.route('/api-test', methods=['POST'])
def dns_register():
    result = {}
    resultInfo = {}
    
    offset = request.args.get('offset')  #位移
    limit = request.args.get('limit')   #最多显示个数
    if not offset:
        offset= 0
    if not limit:
        limit= 500

    try:
        dns = Esearch(url='http://es-server:9200/', index='whois-index', offset=offset, limit=limit)
        otype = request.json.keys()[0]
        olist = request.json[otype]       
        data = dns.search(otype, olist)  
    except Exception:
        result = {
          "data": [],
          "resultInfo": {
            "msg": "请求超时：查询数据的时间超过了最大超时时间，请重新查询或分批查询",
            "ret": 0,
            "retCount": 0,
            "retOffset": offset,
            "total": 0
          }
        }
        return jsonify(result)
    
    if data == "TypeError":
        result = {
          "data": [],
          "resultInfo": {
            "msg": "请求包数据中的查询类型错误,只支持email、domain、phone、username",
            "ret": 0,
            "retCount": 0,
            "retOffset": offset,
            "total": 0
          }
        }
        return jsonify(result)
    
    if data == "TotalError":
        result = {
          "data": [],
          "resultInfo": {
            "msg": "一次性查询量超过了最大限制（一次最多查询200条），请分批查询",
            "ret": 0,
            "retCount": 0,
            "retOffset": offset,
            "total": 0
          }
        }
        return jsonify(result)
        
    resultInfo["retOffset"] = offset
    resultInfo["retCount"] = len(data)
    resultInfo["total"] = 0
    resultInfo["msg"] = "成功"
    resultInfo["ret"] = 1
  
    result["data"] = data
    result["resultInfo"] = resultInfo
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
