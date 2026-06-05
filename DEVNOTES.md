## Additional notes

***This notes are useful for development usages such as debugging and other 
things. It contans a lot of captured infos that can be used to try to fix some 
developed problems. Be avare that those infos may be outdates, so if it's 
possible - do retest to cause the problems. Thanks

Note to myself: this is weird
```
...
[2026-05-22 01:15:15] 2026-05-22 01:15:15,526 [INFO] (Thread-654 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:15:15] 2026-05-22 01:15:15,526 [INFO] (Thread-654 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:15:21] Updating blacklist...
[2026-05-22 01:15:21] Updating blacklist...
[2026-05-22 01:15:21] Blacklist loaded: 79 entries.
[2026-05-22 01:15:21] Blacklist loaded: 79 entries.
[2026-05-22 01:15:58] 2026-05-22 01:15:58,044 [WARNING] (Thread-655 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:15:58] 2026-05-22 01:15:58,044 [WARNING] (Thread-655 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:15:58] 2026-05-22 01:15:58,049 [INFO] (Thread-655 (process_request_thread)) 127.0.0.1 - "GET /api/.env HTTP/1.1" 404 -
[2026-05-22 01:15:58] 2026-05-22 01:15:58,049 [INFO] (Thread-655 (process_request_thread)) 127.0.0.1 - "GET /api/.env HTTP/1.1" 404 -
[2026-05-22 01:16:02] 2026-05-22 01:16:02,801 [WARNING] (Thread-656 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:16:02] 2026-05-22 01:16:02,801 [WARNING] (Thread-656 (process_request_thread)) 127.0.0.1 - code 404, message File not found
[2026-05-22 01:16:02] 2026-05-22 01:16:02,802 [INFO] (Thread-656 (process_request_thread)) 127.0.0.1 - "GET /api/test HTTP/1.1" 404 -
[2026-05-22 01:16:02] 2026-05-22 01:16:02,802 [INFO] (Thread-656 (process_request_thread)) 127.0.0.1 - "GET /api/test HTTP/1.1" 404 -
[2026-05-22 01:16:15] 2026-05-22 01:16:15,649 [INFO] (Thread-657 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:16:15] 2026-05-22 01:16:15,649 [INFO] (Thread-657 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:16:21] Updating blacklist...
[2026-05-22 01:16:21] Updating blacklist...
[2026-05-22 01:16:21] Blacklist loaded: 79 entries.
[2026-05-22 01:16:21] Blacklist loaded: 79 entries.
[2026-05-22 01:17:15] 2026-05-22 01:17:15,791 [INFO] (Thread-658 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
[2026-05-22 01:17:15] 2026-05-22 01:17:15,791 [INFO] (Thread-658 (process_request_thread)) 31.43.251.43 - "POST /beacon/ping HTTP/1.1" 200 -
```
Is that the "config" 404s caused on client that was mentioned in the TODO?
Maybe it's when it drops the internet?


At some point CDN starts to dup the output: -- fixed
```
[2026-05-27 19:33:56] 2026-05-27 19:33:56,889 [INFO] (Thread-205 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/LOxWqcPBBEDfPEfEYxf
[REDACTED]/chunk/0 HTTP/1.1" 200 -
[2026-05-27 19:33:56] 2026-05-27 19:33:56,888 [INFO] (Thread-205 (process_request_thread)) Chunk received: token=LOxWqcPBBEDf… idx=0 (25600KB) 1/261
[2026-05-27 19:33:56] 2026-05-27 19:33:56,888 [INFO] (Thread-205 (process_request_thread)) Chunk received: token=LOxWqcPBBEDf… idx=0 (25600KB) 1/261
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/init HTTP/1.1" 200 
-
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/init HTTP/1.1" 200 
-
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… file=Hacksaw Ridge 
(2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv chunks=261 owner=user
[2026-05-27 19:33:54] 2026-05-27 19:33:54,069 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… file=Hacksaw Ridge 
(2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv chunks=261 owner=user
[2026-05-27 19:33:54] 2026-05-27 19:33:54,066 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… strategy=direct fil
e='Hacksaw Ridge (2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv' size=6834559158 chunks=261
[2026-05-27 19:33:54] 2026-05-27 19:33:54,066 [INFO] (Thread-204 (process_request_thread)) Upload session init: token=LOxWqcPBBEDf… strategy=direct fil
e='Hacksaw Ridge (2016) BDRip 1080p H.265 [2xUKR_ENG] [Hurtom]_1.mkv' size=6834559158 chunks=261
[2026-05-27 19:33:53] 2026-05-27 19:33:53,384 [INFO] (Thread-203 (process_request_thread)) 127.0.0.1 - "POST /api/v1/upload_session/speed_probe HTTP/1.
1" 200 -
[2026-05-27 19:33:53] 2026-05-27 19:33:53,340 [INFO] (Thread-202 (process_request_thread)) 127.0.0.1 - "GET /api/v1/upload_session/config HTTP/1.1" 200
 -
[2026-05-27 19:33:50] Blacklist loaded: 79 entries.
[2026-05-27 19:33:50] Updating blacklist...
[2026-05-27 19:33:43] 2026-05-27 19:33:43,538 [INFO] (Thread-201 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/tmp/METALLICA%20._Best%2
0Magnetic_ HTTP/1.1" 200 -
[2026-05-27 19:33:43] 2026-05-27 19:33:43,457 [INFO] (Thread-200 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/tmp/%D0%A1%D0%B5%D1%81%D
1%96%D1%8F%201%20%E2%80%93%20%D0%BA%D0%BE%D0%BF%D1%96%D1%8F HTTP/1.1" 200 -
[2026-05-27 19:33:43] 2026-05-27 19:33:43,425 [INFO] (Thread-199 (process_request_thread)) 127.0.0.1 - "GET /api/v1/list/tmp HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,957 [INFO] (Thread-198 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/xair HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,877 [INFO] (Thread-197 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/tmp HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,801 [INFO] (Thread-196 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/sort%20later HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,720 [INFO] (Thread-195 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/shareables HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,636 [INFO] (Thread-194 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/sdfsf HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,558 [INFO] (Thread-193 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/Phone HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,481 [INFO] (Thread-192 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/ocr HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,399 [INFO] (Thread-191 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/NewFolder77 HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,318 [INFO] (Thread-190 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/linlap HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,289 [INFO] (Thread-189 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/From_CDN HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,157 [INFO] (Thread-188 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/from%2016GB%20USB%20Thumb HTTP/1.1" 200 -
[2026-05-27 19:33:42] 2026-05-27 19:33:42,081 [INFO] (Thread-187 (process_request_thread)) 127.0.0.1 - "GET /api/v1/foldersize/.trash HTTP/1.1" 200 -
:
```
Also CDN should lock the files so it will never re-read the same folder if worker (for ZIP creation/generation) is started, and the main thing - do not spawn new worker on the same job
Also, need to implement so if ping isn't coming for more than 3 seconds, or otherwise - client cancels the download of ZIP - stop the worker or do something so it will add the files to pending list, and the computed hashes will be saved anyway