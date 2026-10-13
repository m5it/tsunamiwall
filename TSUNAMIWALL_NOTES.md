     1. Per-IP allow/deny                                                                                                 
                                                                                                                          
     You can now restrict a port to a single source IP or CIDR:                                                           
                                                                                                                          
     ./run.sh allow 8080 --ip 203.0.113.45                                                                                
     ./run.sh allow 8080 --ip 203.0.113.0/24                                                                              
     ./run.sh allow --file myports.txt --ip 203.0.113.0/24                                                                
                                                                                                                          
     To remove a per-IP rule later:                                                                                       
                                                                                                                          
     ./run.sh deny 8080 --ip 203.0.113.45                                                                                 
                                                                                                                          
     Global allow 8080 still works as before. Internally the daemon now stores allowed_per_ip and emits per-source-IP/    
     CIDR rules before the global allow rules.                                                                            
                                                                                                                          
     2. scripts/tsunamiwall-logs log viewer                                                                               
                                                                                                                          
     I created an easy-to-use log viewer:                                                                                 
                                                                                                                          
     scripts/tsunamiwall-logs recent          # last 50 hits                                                              
     scripts/tsunamiwall-logs recent 20       # last 20 hits                                                              
     scripts/tsunamiwall-logs tail            # follow live                                                               
     scripts/tsunamiwall-logs by-ip 1.2.3.4                                                                               
     scripts/tsunamiwall-logs by-country US                                                                               
     scripts/tsunamiwall-logs by-dst 10005                                                                                
     scripts/tsunamiwall-logs payloads 1.2.3.4                                                                            
     scripts/tsunamiwall-logs stats                                                                                       
                                                                                                                          
     It reads /var/log/tsunamiwall/hits.logl and the bycountry/ payload tree. Since that directory is root:root 750,      
     run it with sudo to see live data:                                                                                   
                                                                                                                          
     sudo scripts/tsunamiwall-logs recent 20                                                                              
                                                                                                                          
     If run without permissions it now prints a friendly message instead of a traceback.                                  
                                                                                                                          
     Files changed                                                                                                        
                                                                                                                          
     - tsunamiwall/iptables.py — added allowed_per_ip to build_rules                                                      
     - tsunamiwall/daemon.py — stores per-IP allows, passes them to iptables, returns them in status, handles             
       allow_many/deny_many with ip                                                                                       
     - tsunamiwall/cli.py — added --ip IP/CIDR to allow and deny                                                          
     - scripts/tsunamiwall-logs + scripts/tsunamiwall_logs.py — new log viewer                                            
     - tests/test_per_ip_allow.py, tests/test_logview.py — new tests                                                      
     - README.md, docs/usage.md, CHANGELOG.md, AGENTS.md — documentation updated                                          
                                                                                                                          
     Tests                                                                                                                
                                                                                                                          
     All tests pass:                                                                                                      
                                                                                                                          
     .venv/bin/python -m pytest tests/ -v                                                                                 
     # 32 passed, 1 skipped                                                                                               
                                                                                                                          
     You can now try the new commands in your terminal:                                                                   
                                                                                                                          
     ./run.sh -c ~/.config/tsunamiwall/config.yaml allow 8080 --ip <your-ip>                                              
     ./run.sh -c ~/.config/tsunamiwall/config.yaml status                                                                 
     sudo scripts/tsunamiwall-logs recent 20                                                                              
