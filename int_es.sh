#!/bin/bash -x
es_dir=$1

eval `grep MYSQL_PASS /opt/cdnfly/master/conf/config.py`
eval `grep MYSQL_IP /opt/cdnfly/master/conf/config.py`
eval `grep MYSQL_PORT /opt/cdnfly/master/conf/config.py`
eval `grep MYSQL_DB /opt/cdnfly/master/conf/config.py`
eval `grep MYSQL_USER /opt/cdnfly/master/conf/config.py`
eval `grep LOG_PWD /opt/cdnfly/master/conf/config.py`


#判断系统版本
check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''
    local packageSupport=''

    if [[ "$release" == "" ]] || [[ "$systemPackage" == "" ]] || [[ "$packageSupport" == "" ]];then

        if [[ -f /etc/redhat-release ]];then
            release="centos"
            systemPackage="yum"
            packageSupport=true

        elif cat /etc/issue | grep -q -E -i "debian";then
            release="debian"
            systemPackage="apt"
            packageSupport=true

        elif cat /etc/issue | grep -q -E -i "ubuntu";then
            release="ubuntu"
            systemPackage="apt"
            packageSupport=true

        elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat";then
            release="centos"
            systemPackage="yum"
            packageSupport=true

        elif cat /proc/version | grep -q -E -i "debian";then
            release="debian"
            systemPackage="apt"
            packageSupport=true

        elif cat /proc/version | grep -q -E -i "ubuntu";then
            release="ubuntu"
            systemPackage="apt"
            packageSupport=true

        elif cat /proc/version | grep -q -E -i "centos|red hat|redhat";then
            release="centos"
            systemPackage="yum"
            packageSupport=true

        else
            release="other"
            systemPackage="other"
            packageSupport=false
        fi
    fi

    echo -e "release=$release\nsystemPackage=$systemPackage\npackageSupport=$packageSupport\n" > /tmp/ezhttp_sys_check_result

    if [[ $checkType == "sysRelease" ]]; then
        if [ "$value" == "$release" ];then
            return 0
        else
            return 1
        fi

    elif [[ $checkType == "packageManager" ]]; then
        if [ "$value" == "$systemPackage" ];then
            return 0
        else
            return 1
        fi

    elif [[ $checkType == "packageSupport" ]]; then
        if $packageSupport;then
            return 0
        else
            return 1
        fi
    fi
}

# 存储目录
if [[  `echo $es_dir | grep -E "^/"` == "" ]];then
    echo "please input a valid dir."
    exit 1
fi 

if [[ $es_dir == "/" ]];then
    echo "es_dir eq / "
    exit 1
fi

eval `grep "VERSION_NUM" /opt/cdnfly/master/conf/config.py`

sed -i "s#path.data.*#path.data: $es_dir#g" /etc/elasticsearch/elasticsearch.yml
mkdir -p $es_dir
chown -R elasticsearch $es_dir

service elasticsearch stop
iptables -I INPUT -p tcp --dport 9200 -j DROP
iptables -I INPUT -p tcp -s 127.0.0.1 -j ACCEPT
es_path=`awk '/path.data/{print $2}' /etc/elasticsearch/elasticsearch.yml`
if [[ $es_path == "" ]];then
    echo "empty es_path"
    exit 1
fi

if [[ $es_path == "/" ]];then
    echo "es_path eq / "
    exit 1
fi

http_value="300"
https_value="5300"

# 清空目录并设置密码
rm -rf $es_path/nodes
password=`awk -F'=' '/LOG_PWD/{gsub("\"","",$2);print $2}' /opt/cdnfly/master/conf/config.py`
echo $password | /usr/share/elasticsearch/bin/elasticsearch-keystore add -xf bootstrap.password
service elasticsearch start
sleep 5
curl -H "Content-Type:application/json" -XPOST -u elastic:$password 'http://127.0.0.1:9200/_xpack/security/user/elastic/_password' -d "{ \"password\" : \"$password\" }"

curl -u elastic:$password -X PUT "localhost:9200/_ilm/policy/access_log_policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "200gb",
            "max_age": "1d" 
          }
        }
      },
      "delete": {
        "min_age": "7d",
        "actions": {
          "delete": {} 
        }
      }
    }
  }
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_ilm/policy/node_log_policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_age": "1d" 
          }
        }
      },
      "delete": {
        "min_age": "7d",
        "actions": {
          "delete": {} 
        }
      }
    }
  }
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/http_access_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "nid":    { "type": "keyword" },  
      "uid":    { "type": "keyword" },  
      "upid":    { "type": "keyword" },  
      "time":   { "type": "date"  ,"format":"dd/MMM/yyyy:HH:mm:ss Z"},
      "addr":  { "type": "keyword"  }, 
      "method":  { "type": "text" , "index":false }, 
      "scheme":  { "type": "keyword"  }, 
      "host":  { "type": "keyword"  }, 
      "server_port":  { "type": "keyword"  }, 
      "req_uri":  { "type": "keyword"  }, 
      "protocol":  { "type": "text" , "index":false }, 
      "status":  { "type": "keyword"  }, 
      "bytes_sent":  { "type": "integer"  }, 
      "referer":  { "type": "keyword"  }, 
      "user_agent":  { "type": "text" , "index":false }, 
      "content_type":  { "type": "text" , "index":false }, 
      "up_resp_time":  { "type": "float" , "index":false,"ignore_malformed": true }, 
      "cache_status":  { "type": "keyword"  }, 
      "up_recv":  { "type": "integer", "index":false,"ignore_malformed": true  }
    }
  },  
  "index_patterns": ["http_access-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "access_log_policy", 
    "index.lifecycle.rollover_alias": "http_access"
  }
}
'

curl -u elastic:$password  -X PUT "localhost:9200/http_access-000001?pretty" -H 'Content-Type: application/json' -d'
{

  "aliases": {
    "http_access":{
      "is_write_index": true 
    }
  }  
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/stream_access_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "nid":    { "type": "keyword" },
      "uid":    { "type": "keyword" },
      "upid":    { "type": "keyword" },
      "port":  { "type": "keyword"  }, 
      "addr":  { "type": "keyword"  }, 
      "time":   { "type": "date"  ,"format":"dd/MMM/yyyy:HH:mm:ss Z"},
      "status":  { "type": "keyword"  }, 
      "bytes_sent":  { "type": "integer" , "index":false }, 
      "bytes_received":  { "type": "keyword"  }, 
      "session_time":  { "type": "integer" , "index":false }
    }
  },  
  "index_patterns": ["stream_access-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "access_log_policy", 
    "index.lifecycle.rollover_alias": "stream_access"
  }
}
'
curl -u elastic:$password  -X PUT "localhost:9200/stream_access-000001?pretty" -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "stream_access":{
      "is_write_index": true 
    }
  } 
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/bandwidth_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "time":   { "type": "date"  ,"format":"yyyy-MM-dd HH:mm:ss"},
      "node_id":  { "type": "keyword"  },
      "nic":  { "type": "keyword"  },
      "inbound":  { "type": "long", "index":false  },
      "outbound":  { "type": "long", "index":false  }
    }
  },  
  "index_patterns": ["bandwidth-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "node_log_policy", 
    "index.lifecycle.rollover_alias": "bandwidth"
  }
}
'
curl -u elastic:$password  -X PUT "localhost:9200/bandwidth-000001?pretty" -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "bandwidth":{
      "is_write_index": true 
    }
  } 
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/nginx_status_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "time":   { "type": "date"  ,"format":"yyyy-MM-dd HH:mm:ss"},
      "node_id":  { "type": "keyword"  },
      "active_conn":  { "type": "integer" , "index":false }, 
      "reading":  { "type": "integer" , "index":false }, 
      "writing":  { "type": "integer" , "index":false }, 
      "waiting":  { "type": "integer" , "index":false }
    }
  },  
  "index_patterns": ["nginx_status-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "node_log_policy", 
    "index.lifecycle.rollover_alias": "nginx_status"
  }
}
'
curl -u elastic:$password  -X PUT "localhost:9200/nginx_status-000001?pretty" -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "nginx_status":{
      "is_write_index": true 
    }
  } 
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/sys_load_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "time":   { "type": "date"  ,"format":"yyyy-MM-dd HH:mm:ss"},
      "node_id":  { "type": "keyword"  },
      "cpu":  { "type": "float" , "index":false },
      "load":  { "type": "float" , "index":false },
      "mem":  { "type": "float" , "index":false }
    }
  },  
  "index_patterns": ["sys_load-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "node_log_policy", 
    "index.lifecycle.rollover_alias": "sys_load"
  }
}
'
curl -u elastic:$password  -X PUT "localhost:9200/sys_load-000001?pretty" -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "sys_load":{
      "is_write_index": true 
    }
  } 
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/disk_usage_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "time":   { "type": "date"  ,"format":"yyyy-MM-dd HH:mm:ss"},
      "node_id":  { "type": "keyword"  },
      "path":  { "type": "keyword"  },
      "space":  { "type": "float" , "index":false },
      "inode":  { "type": "float" , "index":false }      
    }
  },  
  "index_patterns": ["disk_usage-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "node_log_policy", 
    "index.lifecycle.rollover_alias": "disk_usage"
  }
}
'
curl -u elastic:$password  -X PUT "localhost:9200/disk_usage-000001?pretty" -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "disk_usage":{
      "is_write_index": true 
    }
  } 
}
'

curl -u elastic:$password  -X PUT "localhost:9200/_template/tcp_conn_template" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "time":   { "type": "date"  ,"format":"yyyy-MM-dd HH:mm:ss"},
      "node_id":  { "type": "keyword"  },
      "conn":  { "type": "integer" , "index":false }
    }
  },  
  "index_patterns": ["tcp_conn-*"], 
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.lifecycle.name": "node_log_policy", 
    "index.lifecycle.rollover_alias": "tcp_conn"
  }
}
'
curl -u elastic:$password  -X PUT "localhost:9200/tcp_conn-000001?pretty" -H 'Content-Type: application/json' -d'
{
  "aliases": {
    "tcp_conn":{
      "is_write_index": true 
    }
  } 
}
'

# pipeline nginx_access_pipeline
curl -u elastic:$password -X PUT "localhost:9200/_ingest/pipeline/nginx_access_pipeline?pretty" -H 'Content-Type: application/json' -d'
{
  "description" : "nginx access pipeline",
  "processors" : [
      {
        "grok": {
          "field": "message",
          "patterns": ["%{DATA:nid}\t%{DATA:uid}\t%{DATA:upid}\t%{DATA:time}\t%{DATA:addr}\t%{DATA:method}\t%{DATA:scheme}\t%{DATA:host}\t%{DATA:server_port}\t%{DATA:req_uri}\t%{DATA:protocol}\t%{DATA:status}\t%{DATA:bytes_sent}\t%{DATA:referer}\t%{DATA:user_agent}\t%{DATA:content_type}\t%{DATA:up_resp_time}\t%{DATA:cache_status}\t%{GREEDYDATA:up_recv}"]
        }
      },
      {
          "remove": {
            "field": "message"
          }      
      }       
  ]
}
'

# stream_access_pipeline
curl -u elastic:$password -X PUT "localhost:9200/_ingest/pipeline/stream_access_pipeline?pretty" -H 'Content-Type: application/json' -d'
{
  "description" : "stream access pipeline",
  "processors" : [
      {
        "grok": {
          "field": "message",
          "patterns": ["%{DATA:nid}\t%{DATA:uid}\t%{DATA:upid}\t%{DATA:port}\t%{DATA:addr}\t%{DATA:time}\t%{DATA:status}\t%{DATA:bytes_sent}\t%{DATA:bytes_received}\t%{GREEDYDATA:session_time}"]
        }
      },
      {
          "remove": {
            "field": "message"
          }      
      } 
  ]
}
'

# monitor_pipeline
curl -u elastic:$password -X PUT "localhost:9200/_ingest/pipeline/monitor_pipeline?pretty" -H 'Content-Type: application/json' -d'
{
  "description" : "monitor pipeline",
  "processors" : [
      {
        "json" : {
          "field" : "message",
          "add_to_root" : true
        }
      },
      {
          "remove": {
            "field": "message"
          }      
      } 
  ]
}
'

# black_ip
curl -u elastic:$password  -X PUT "localhost:9200/black_ip" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "site_id":    { "type": "keyword" },  
      "ip":    { "type": "keyword" },  
      "filter":    { "type": "text" , "index":false }, 
      "uid":  { "type": "keyword"  }, 
      "exp":  { "type": "keyword"  }, 
      "create_at":  { "type": "keyword"  }
    }
  }
}
'

# white_ip
curl -u elastic:$password  -X PUT "localhost:9200/white_ip" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "site_id":    { "type": "keyword" },  
      "ip":    { "type": "keyword" },  
      "exp":  { "type": "keyword"  }, 
      "create_at":  { "type": "keyword"  }
    }
  }
}
'

# auto_swtich
curl -u elastic:$password  -X PUT "localhost:9200/auto_switch" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "host":  { "type": "text" , "index":false },
      "rule":  { "type": "text" , "index":false },
      "end_at":  { "type": "integer", "index":true }
    }
  }
}
'

# up_res_usage
curl -u elastic:$password  -X PUT "localhost:9200/up_res_usage" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "upid":    { "type": "keyword" },  
      "node_id":    { "type": "keyword" },  
      "bandwidth":    { "type": "integer" , "index":false }, 
      "connection":  { "type": "integer" , "index":false }, 
      "time": { "type": "keyword" }
    }
  }
}
'

# up_res_limit
curl -u elastic:$password  -X PUT "localhost:9200/up_res_limit" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "upid":    { "type": "keyword" },  
      "node_id":    { "type": "keyword" },  
      "bandwidth":    { "type": "integer" , "index":false }, 
      "connection":  { "type": "integer" , "index":false }, 
      "expire":  { "type": "keyword" }
    }
  }
}
'


# 设置保留天数
# access_log

value=`mysql -N -h$MYSQL_IP -u$MYSQL_USER -p$MYSQL_PASS -P$MYSQL_PORT $MYSQL_DB -e "select value from config where name='keep-access-log-days'"`
if [[ "$value" == "" ]];then
  value="1"
fi

curl -uelastic:$LOG_PWD -v -H "Content-Type: application/json" -X PUT "http://127.0.0.1:9200/_ilm/policy/access_log_policy" -d "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_age\":\"1d\"}}},\"delete\":{\"min_age\":\"${value}d\",\"actions\":{\"delete\":{}}}}}}" 

# node_log
value=`mysql -N -h$MYSQL_IP -u$MYSQL_USER -p$MYSQL_PASS -P$MYSQL_PORT $MYSQL_DB -e "select value from config where name='keep-node-log-days'"`
if [[ "$value" == "" ]];then
  value="1"
fi
curl -uelastic:$LOG_PWD -v -H "Content-Type: application/json" -X PUT "http://127.0.0.1:9200/_ilm/policy/node_log_policy" -d "{\"policy\":{\"phases\":{\"hot\":{\"actions\":{\"rollover\":{\"max_age\":\"1d\"}}},\"delete\":{\"min_age\":\"${value}d\",\"actions\":{\"delete\":{}}}}}}" 

if check_sys sysRelease ubuntu;then
    apt -y install iptables

elif check_sys sysRelease debian;then
    apt -y install iptables

elif check_sys sysRelease centos;then
    yum install -y iptables

fi   

for i in `seq $(iptables -nL | grep -c 9200)`;do
  iptables -D INPUT -p tcp --dport 9200 -j DROP || true
  iptables -D INPUT -p tcp -s 127.0.0.1 -j ACCEPT || true
done


