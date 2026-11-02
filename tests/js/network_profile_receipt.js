// Pure shipped receipt validator; no browser, network, secret storage or reimplementation.
module.exports = function checkReceipt(source) {
  const window = {};
  new Function('window', source)(window);
  const receipt = window.TwnNetworkProfileReceipt;
  const assert = (ok, message) => { if (!ok) throw new Error(message); };
  const cases = [
    ['snmp','credentials',{name:' Credential ',version:'v2c',community:'not returned'}, {name:'Credential',version:'v2c',has_community:true}, {version:'v3'}],
    ['snmp','credentials',{name:'V3',version:'v3',username:' operator ',security_level:'authpriv',auth_protocol:'sha256',priv_protocol:'aes128',context_name:' context '}, {name:'V3',version:'v3',username:'operator',security_level:'authpriv',auth_protocol:'sha256',priv_protocol:'aes128',context_name:'context',has_auth_key:true,has_priv_key:true}, {username:'wrong',security_level:'authnopriv',auth_protocol:'sha1',priv_protocol:'aes256',context_name:'wrong',has_auth_key:false,has_priv_key:false}],
    ['snmp','hosts',{name:'Host',host:' 192.0.2.20 ',port:'0161',credential_name:'Credential',timeout:'2.5',retries:'2'}, {name:'Host',host:'192.0.2.20',port:161,credential_name:'Credential',timeout:2.5,retries:2}, {host:'192.0.2.99',port:162,credential_name:'Other',timeout:3,retries:1}],
    ['snmp','oids',{name:'OID',source:'#comment\r\n Clock = 1.3.6.1.2.1.1.3.0\u0085Other = 1.3.6.1.2.1.1.1.0'}, {name:'OID',count:2}, {count:1}],
    ['radius','servers',{name:'Server',host:'192.0.2.44',port:'1812'}, {name:'Server',host:'192.0.2.44',port:1812}, {host:'192.0.2.99',port:1813}],
    ['radius','credentials',{name:'RADIUS user',username:' fixture '}, {name:'RADIUS user',username:'fixture'}, {username:'wrong'}],
    ['radius','attributes',{name:'Attributes',attributes:'# comment\r\n#26:9 = deadbeef\r\nNAS-Identifier = fixture'}, {name:'Attributes',count:2}, {count:1}],
  ];
  const passed = [];
  for (const [tool,kind,input,saved,wrong] of cases) {
    const submitted = new Map(Object.entries(input));
    assert(receipt.verify(tool,kind,saved,submitted), `${tool}/${kind} valid canonical receipt rejected`);
    for (const [key,value] of Object.entries(wrong)) {
      assert(!receipt.verify(tool,kind,{...saved,[key]:value},submitted), `${tool}/${kind} accepted same-name wrong ${key}`);
    }
    assert(!receipt.verify(tool,kind,{...saved,name:'Other'},submitted),'wrong-name receipt accepted');
    passed.push(`${tool}/${kind} canonical receipt and same-name wrong metadata`);
  }
  for (const level of ['noauthnopriv','authnopriv','authpriv']) {
    const body=new Map([['name','Modes'],['version','v3'],['username','user'],['security_level',level],['auth_protocol','sha256'],['priv_protocol','aes128'],['context_name','']]);
    const profile={name:'Modes',version:'v3',username:'user',security_level:level,auth_protocol:'sha256',priv_protocol:'aes128',context_name:'',has_auth_key:level!=='noauthnopriv',has_priv_key:level==='authpriv'};
    assert(receipt.verify('snmp','credentials',profile,body),'valid mode/presence rejected');
    assert(!receipt.verify('snmp','credentials',{...profile,has_auth_key:!profile.has_auth_key},body),'contradictory auth presence accepted');
    assert(!receipt.verify('snmp','credentials',{...profile,has_priv_key:!profile.has_priv_key},body),'contradictory privacy presence accepted');
  }
  passed.push('V3 secret presence matches all security levels');
  const original = new Map([['name','Server'],['host','192.0.2.44'],['port','1812']]);
  const newerDraft = new Map(original); newerDraft.set('host','192.0.2.99');
  const saved = {name:'Server',host:'192.0.2.44',port:1812};
  assert(receipt.verify('radius','servers',saved,original) && !receipt.verify('radius','servers',saved,newerDraft),'comparison did not bind submitted snapshot');
  passed.push('receipt binds captured submission rather than newer draft');
  const unicode = '😀'.repeat(100);
  assert(receipt.validName({name:unicode}) && !receipt.validName({name:unicode+'x'}),'Unicode codepoint name limit differs from server');
  assert(receipt.verify('snmp','credentials',{name:unicode,version:'v2c',has_community:true},new Map([['name',unicode],['version','v2c']])),'Unicode receipt rejected');
  assert(receipt.strip('\u0085\u001c Name \u3000')==='Name' && receipt.strip('\ufeffName')==='\ufeffName','Python whitespace/BOM semantics changed');
  passed.push('Unicode length and Python whitespace semantics');
  for(const key of ['port','count']) {
    const tool=key==='port'?'radius':'snmp',kind=key==='port'?'servers':'oids';
    const input=key==='port'?new Map([['name','N'],['host','192.0.2.1'],['port','1812']]):new Map([['name','N'],['source','Clock = 1.3.6.1.2.1.1.3.0']]);
    const value=key==='port'?{name:'N',host:'192.0.2.1',port:'1812'}:{name:'N',count:'1'};
    assert(!receipt.verify(tool,kind,value,input),'numeric string ACK accepted as canonical numeric metadata');
  }
  passed.push('numeric ACK metadata requires canonical types');
  return passed;
};
