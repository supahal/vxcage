#2015.01.06 -   ALD
#   VXCAGE plugin for cuckoo sandboxing
#   Modification History:
#       2014.01.06  -   ALD - Initial revision

#!/usr/bin/env python

import os
from objects import File
from database import Database
from utils import jsonize, store_sample

class Vxplugin():
    def __init__( self ):
        self.db = Database()

    def add_malware( self , data , tags = '' ):
        if not os.path.exists( data ):
            return False

        file_data = open( data , "rb" ).read()
        info = File(file_path=store_sample(file_data))
        self.db.add(obj=info, file_name=os.path.basename(data), tags=tags)
        
        return True

    def list_tags( self ):
        rows = self.db.list_tags()
        result = []
        results = []
        for row in rows:
            results.append(row.tag)

        return results
        
    def find_malware( self , key , value ):
        def details(row):
            tags = []
            for tag in row.tag:
                tags.append(tag.tag)

            entry = {
                "id" : row.id,
                "file_name" : row.file_name,
                "file_type" : row.file_type,
                "file_size" : row.file_size,
                "md5" : row.md5,
                "sha1" : row.sha1,
                "sha256" : row.sha256,
                "sha512" : row.sha512,
                "crc32" : row.crc32,
                "ssdeep": row.ssdeep,
                "created_at": row.created_at.__str__(),
                "tags" : tags
            }

            return entry
        
        if not key or not value:
            return None

        if key == 'md5':
            row = self.db.find_md5(value)
            if row:
                return jsonize(details(row))
            else:
                print("File not found")
                return None
        elif key == 'sha256':
            row = self.db.find_sha256(value)
            if row:
                return jsonize(details(row))
            else:
                print("File not found")            
        else:
            if key == 'ssdeep':
                rows = self.db.find_ssdeep(value)
            elif key == 'tag':
                rows = self.db.find_tag(value)
            elif key == 'date':
                rows = self.db.find_date(value)
            else:
                print("Invalid search term")
                return None

        if not rows:
            print("File not found")
            return None

        results = []
        for row in rows:
            entry = details(row)
            results.append(entry)
                
        return jsonize(results)
        

if __name__ == '__main__':
    #DEBUG:
    vx = Vxplugin()
    vx.add_malware("/root/Desktop/KINS/test/test.exe",'zbot,kins,zeusvm')
    print vx.list_tags()
    print vx.find_malware('sha256','6bb85dda8d1ddaf8606ba4562d29c02475f2fea48022106a81729100ca18eb65')       
    print vx.find_malware('tag','zbot')       
    print vx.find_malware('date','2015-01-07')       
    print vx.find_malware('md5','3de6d8fe9bacea262dac9595053b7f8f')       
    print vx.find_malware('md5ds','3de6d8fe9bacea262dac9595053b7f8f')
else:
    print "Import - VXCAGE-PLUGIN"
