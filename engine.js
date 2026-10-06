/* PcapLens engine - classic pcap file parser.
   Global header (LE/BE, us/ns), packet records, decode Ethernet/VLAN,
   IPv4 (checksum verified), IPv6, TCP, UDP, ICMP, ICMPv6 echo, ARP, DNS.
   No deps. Browser global PcapLens, or module.exports in node. */
(function(root){
'use strict';
var ETYPES={0x0800:'IPv4',0x0806:'ARP',0x86DD:'IPv6',0x8100:'VLAN',0x8847:'MPLS',0x88CC:'LLDP'};
var PROTOS={1:'ICMP',2:'IGMP',6:'TCP',17:'UDP',41:'IPv6',47:'GRE',58:'ICMPv6',89:'OSPF'};
function mac(b,o){var s=[];for(var i=0;i<6;i++)s.push(('0'+b[o+i].toString(16)).slice(-2));return s.join(':');}
function ip4(b,o){return b[o]+'.'+b[o+1]+'.'+b[o+2]+'.'+b[o+3];}
function ip6(b,o){
  var g=[],i;
  for(i=0;i<16;i+=2)g.push(((b[o+i]<<8)|b[o+i+1]).toString(16));
  /* RFC 5952 longest zero-run compression */
  var best=-1,blen=0,cur=-1,cl=0;
  for(i=0;i<8;i++){if(g[i]==='0'){if(cur<0){cur=i;cl=1;}else cl++;if(cl>blen){blen=cl;best=cur;}}else cur=-1;}
  var parts=[];
  for(i=0;i<8;i++){
    if(i===best){parts.push('');i+=blen-1;if(i===7)parts.push('');continue;}
    parts.push(g[i]);
  }
  var s=parts.join(':');
  return s.replace(/:{3,}/,'::');
}
function u16(b,o){return (b[o]<<8)|b[o+1];}
function u32(b,o){return ((b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3])>>>0;}
function cksum16(b,off,len){
  var s=0,i;
  for(i=0;i+1<len;i+=2)s+=u16(b,off+i);
  if(len%2)s+=b[off+len-1]<<8;
  while(s>>16)s=(s&0xFFFF)+(s>>16);
  return s;
}
function dnsName(b,off,base,depth){
  var labels=[],p=off,jumped=false,end=off,hops=0;
  while(true){
    if(p>=b.length)return {name:labels.join('.')+'.',end:end,truncated:true};
    var l=b[p];
    if(l===0){if(!jumped)end=p+1;return {name:labels.length?labels.join('.')+'.':'.',end:end};}
    if((l&0xC0)===0xC0){
      if(p+1>=b.length)return {name:labels.join('.')+'.',end:end,truncated:true};
      var ptr=((l&0x3F)<<8)|b[p+1];
      if(!jumped)end=p+2;
      if(++hops>16)return {name:labels.join('.')+'.',end:end,truncated:true};
      p=ptr;jumped=true;continue;
    }
    p++;
    if(p+l>b.length)return {name:labels.join('.')+'.',end:end,truncated:true};
    labels.push(txt(b,p,l));p+=l;
    if(!jumped)end=p;
  }
}
function txt(b,o,l){var s='',i;for(i=0;i<l;i++)s+=String.fromCharCode(b[o+i]);try{return decodeURIComponent(escape(s));}catch(e){return s;}}
function parsePcap(bytes){
  var errors=[],warnings=[],packets=[];
  if(bytes.length<24){errors.push('file too short for a pcap global header');return {errors:errors,warnings:warnings,packets:packets};}
  var m0=bytes[0],m1=bytes[1],m2=bytes[2],m3=bytes[3];
  var little,nano=false;
  if(m0===0xd4&&m1===0xc3&&m2===0xb2&&m3===0xa1)little=true;
  else if(m0===0xa1&&m1===0xb2&&m2===0xc3&&m3===0xd4)little=false;
  else if(m0===0x4d&&m1===0x3c&&m2===0xb2&&m3===0xa1){little=true;nano=true;}
  else if(m0===0xa1&&m1===0xb2&&m2===0x3c&&m3===0x4d){little=false;nano=true;}
  else {errors.push('bad magic - not a classic pcap file');return {errors:errors,warnings:warnings,packets:packets};}
  function u16h(o){return little?(bytes[o]|(bytes[o+1]<<8)):((bytes[o]<<8)|bytes[o+1]);}
  function u32h(o){return little?((bytes[o]|(bytes[o+1]<<8)|(bytes[o+2]<<16)|(bytes[o+3]<<24))>>>0):u32(bytes,o);}
  var vmaj=u16h(4),vmin=u16h(6),snaplen=u32h(16),linktype=u32h(20);
  if(linktype!==1)warnings.push('link type '+linktype+' (only LINKTYPE_ETHERNET=1 is decoded)');
  var off=24,idx=0;
  while(off<bytes.length){
    if(off+16>bytes.length){warnings.push('truncated packet record header at offset '+off);break;}
    var ts_sec=u32h(off),ts_frac=u32h(off+4),incl=u32h(off+8),orig=u32h(off+12);
    if(off+16+incl>bytes.length){warnings.push('packet '+idx+' data truncated ('+(bytes.length-off-16)+' of '+incl+' bytes)');incl=bytes.length-off-16;}
    var body=bytes.slice(off+16,off+16+incl);
    packets.push(decodePacket(body,idx,ts_sec,ts_frac,incl,orig,nano,off,warnings));
    off+=16+incl;idx++;
  }
  return {errors:errors,warnings:warnings,packets:packets,nano:nano,little_endian:little,
          version:[vmaj,vmin],snaplen:snaplen,linktype:linktype,size:bytes.length};
}
function decodePacket(b,idx,ts_sec,ts_frac,incl,orig,nano,offset,warnings){
  var p={i:idx,ts_sec:ts_sec,ts_frac:ts_frac,ts:ts_sec+ts_frac/(nano?1e9:1e6),
         incl_len:incl,orig_len:orig,offset:offset,layers:[],len:b.length};
  if(incl<orig)warnings.push('packet '+idx+' captured '+incl+' of '+orig+' bytes (snaplen cut)');
  if(b.length<14){warnings.push('packet '+idx+' too short for Ethernet');return p;}
  var eth={src:mac(b,6),dst:mac(b,0),type:u16(b,12),type_name:ETYPES[u16(b,12)]||('0x'+u16(b,12).toString(16))};
  p.eth=eth;p.layers.push('eth');
  var off=14;
  if(eth.type===0x8100){
    if(b.length<18){warnings.push('packet '+idx+' truncated VLAN');return p;}
    eth.vlan={id:u16(b,14)&0x0FFF,pcp:(b[14]>>5)&7};
    eth.type=u16(b,16);eth.type_name=ETYPES[eth.type]||('0x'+eth.type.toString(16));
    off=18;
  }
  if(eth.type===0x0800){
    if(b.length<off+20){warnings.push('packet '+idx+' truncated IPv4');return p;}
    var ihl=(b[off]&0x0F)*4;
    var ip={version:b[off]>>4,ihl_words:b[off]&0x0F,src:ip4(b,off+12),dst:ip4(b,off+16),
            proto:b[off+9],proto_name:PROTOS[b[off+9]]||('proto-'+b[off+9]),ttl:b[off+8],
            len:u16(b,off+2),id:u16(b,off+4),flags:(b[off+6]>>5)&7,frag_off:u16(b,off+6)&0x1FFF,
            chksum:u16(b,off+10)};
    ip.chksum_ok=cksum16(b,off,ihl)===0xFFFF;
    p.ip=ip;p.layers.push('ipv4');
    p.payload_len=Math.max(0,ip.len-ihl);
    var l4=off+ihl;
    if(ip.proto===6)p.tcp=decodeTCP(b,l4,ip,p,warnings,idx);
    else if(ip.proto===17){p.udp=decodeUDP(b,l4,p,warnings,idx);maybeDNS(b,l4,p);}
    else if(ip.proto===1)p.icmp=decodeICMP(b,l4,p,warnings,idx);
  } else if(eth.type===0x86DD){
    if(b.length<off+40){warnings.push('packet '+idx+' truncated IPv6');return p;}
    var v6={version:b[off]>>4,src:ip6(b,off+8),dst:ip6(b,off+24),nh:b[off+6],
            nh_name:PROTOS[b[off+6]]||('nh-'+b[off+6]),hlim:b[off+7],plen:u16(b,off+4)};
    p.ipv6=v6;p.layers.push('ipv6');
    p.payload_len=v6.plen;
    var l6=off+40;
    if(v6.nh===6)p.tcp=decodeTCP(b,l6,null,p,warnings,idx);
    else if(v6.nh===17)p.udp=decodeUDP(b,l6,p,warnings,idx);
    else if(v6.nh===58){
      if(b.length>=l6+8&&(b[l6]===128||b[l6]===129)){
        p.icmpv6={kind:b[l6]===128?'icmpv6_echo_request':'icmpv6_echo_reply',id:u16(b,l6+4),seq:u16(b,l6+6)};
        p.layers.push('icmpv6');
      }
    }
  } else if(eth.type===0x0806){
    if(b.length<off+28){warnings.push('packet '+idx+' truncated ARP');return p;}
    p.arp={htype:u16(b,off),ptype:u16(b,off+2),op:u16(b,off+6),
           op_name:u16(b,off+6)===1?'who-has':(u16(b,off+6)===2?'is-at':'op-'+u16(b,off+6)),
           hwsrc:mac(b,off+8),psrc:ip4(b,off+14),hwdst:mac(b,off+18),pdst:ip4(b,off+24)};
    p.layers.push('arp');
    p.payload_len=Math.max(0,b.length-off-28);
  }
  if(p.payload_len===undefined)p.payload_len=0;
  return p;
}
function decodeTCP(b,off,ip,p,warnings,idx){
  if(b.length<off+20){warnings.push('packet '+idx+' truncated TCP');return null;}
  p.layers.push('tcp');
  var fl=b[off+13];
  var flags=''; /* scapy letter order: F S R P A U E C */
  if(fl&0x01)flags+='F';if(fl&0x02)flags+='S';if(fl&0x04)flags+='R';
  if(fl&0x08)flags+='P';if(fl&0x10)flags+='A';if(fl&0x20)flags+='U';
  if(fl&0x40)flags+='E';if(fl&0x80)flags+='C';
  return {sport:u16(b,off),dport:u16(b,off+2),seq:u32(b,off+4),ack:u32(b,off+8),
          data_offset:(b[off+12]>>4)*4,flags:flags||'0',window:u16(b,off+14),chksum:u16(b,off+16)};
}
function decodeUDP(b,off,p,warnings,idx){
  if(b.length<off+8){warnings.push('packet '+idx+' truncated UDP');return null;}
  p.layers.push('udp');
  return {sport:u16(b,off),dport:u16(b,off+2),len:u16(b,off+4),chksum:u16(b,off+6)};
}
function decodeICMP(b,off,p,warnings,idx){
  if(b.length<off+4){warnings.push('packet '+idx+' truncated ICMP');return null;}
  p.layers.push('icmp');
  var d={type:b[off],code:b[off+1]};
  if(b.length>=off+8&&(b[off]===0||b[off]===8)){d.id=u16(b,off+4);d.seq=u16(b,off+6);}
  return d;
}
function maybeDNS(b,udpOff,p){
  var u=p.udp;
  if(!u||(u.sport!==53&&u.dport!==53))return;
  var off=udpOff+8;
  if(b.length<off+12)return;
  var dns={id:u16(b,off),qr:(b[off+2]>>7)&1,opcode:(b[off+2]>>3)&0xF,
           rcode:b[off+3]&0xF,qdcount:u16(b,off+4),ancount:u16(b,off+6)};
  var q=off+12;
  if(dns.qdcount>0){
    var n=dnsName(b,q,off);
    dns.qname=n.name;
    if(!n.truncated&&n.end+4<=b.length){dns.qtype=u16(b,n.end);dns.qclass=u16(b,n.end+2);
      /* first answer */
      if(dns.ancount>0){
        var an=n.end+4;
        var an2=dnsName(b,an,off);
        if(!an2.truncated&&an2.end+10<=b.length){
          var atype=u16(b,an2.end),ardlen=u16(b,an2.end+8);
          dns.ttl=u32(b,an2.end+4);
          if(atype===1&&ardlen===4&&an2.end+10+4<=b.length)dns.answer=ip4(b,an2.end+10);
        }
      }
    }
  }
  p.dns=dns;p.layers.push('dns');
}
var api={parsePcap:parsePcap,cksum16:cksum16,ip6:ip6,dnsName:dnsName};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
root.PcapLens=api;
})(typeof self!=='undefined'?self:this);
