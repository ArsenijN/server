## Additional notes

***This notes are useful for development usages such as debugging and other 
things. It contans a lot of captured infos that can be used to try to fix some 
developed problems. Be avare that those infos may be outdates, so if it's 
possible - do retest to cause the problems. Thanks

Note to myself:
Also CDN should lock the files so it will never re-read the same folder if 
worker (for ZIP creation/generation) is started, and the main thing - do not 
spawn new worker on the same job
Also, need to implement so if ping isn't coming for more than 3 seconds, or 
otherwise - client cancels the download of ZIP - stop the worker or do 
something so it will add the files to pending list, and the computed hashes 
will be saved anyway