# sudo mn   --topo tree,2,2   --controller remote,ip=127.0.0.1,port=6653   --switch ovsk,protocols=OpenFlow13
# sudo mn   --topo tree,3,3   --controller remote,ip=127.0.0.1,port=6653   --switch ovsk,protocols=OpenFlow13
# sudo mn   --topo linear,6   --controller remote,ip=127.0.0.1,port=6653   --switch ovsk,protocols=OpenFlow13
# sudo mn   --topo reversed,4   --controller remote,ip=127.0.0.1,port=6653   --switch ovsk,protocols=OpenFlow13
sudo mn   --topo torus,3,3   --controller remote,ip=127.0.0.1,port=6653   --switch ovsk,protocols=OpenFlow13
