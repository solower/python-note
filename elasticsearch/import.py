# -*- coding: utf-8 -*-

from datetime import datetime
from elasticsearch import helpers
from elasticsearch import Elasticsearch

class ElasticBase(object):  
      
    def __init__(self, elastic, index, type):
        self._elastic = elastic
        self._index = index
        self._type = type
        self.create()
        
    def create(self):       
        if not self._elastic.indices.exists(self._index):        
            self._elastic.indices.create(self._index, ignore=[400]) 
    
    def insert(self, dsl, id=None):       
        if not isinstance(dsl, dict):
            raise Exception("Error: need a dict type argu argument")
        dsl['date'] = datetime.now()
        action = {            
            "_index": self._index,
            "_type": self._type,
            "_id": id,
            "_source": dsl
        }            
        helpers.bulk(self._elastic, [action]) 

portinfo = {
          "22": {
            "product": "",
            "state": "open",
            "version": "",
            "name": "ssh",
            "conf": "3",
            "extrainfo": "",
            "reason": "syn-ack",
            "cpe": ""
          },
          "80": {
            "product": "",
            "state": "open",
            "version": "",
            "name": "http",
            "conf": "3",
            "script": {
              "http-title": "Welcome to nginx!"
            },
            "extrainfo": "",
            "reason": "syn-ack",
            "cpe": ""
          },
          "5000": {
            "product": "",
            "state": "open",
            "version": "",
            "name": "upnp",
            "conf": "3",
            "extrainfo": "",
            "reason": "syn-ack",
            "cpe": ""
          }
        }

myes = Elasticsearch("http://172.16.3.166:9200/")    
es = ElasticBase(elastic=myes,index="myindex",type="mytype")
es.insert(mydns)